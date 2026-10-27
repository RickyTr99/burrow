/*
 * Entry point: the loader of an emulated execve() when BURROW is in the
 * environment, the launcher otherwise:
 *
 *   burrow -r ROOTFS [-b HOST[:GUEST]]... [-w GUEST_DIR] [-d DNS_PORT] [-s STATS_FILE] [--] PROGRAM [ARG]...
 *
 * The launcher stays as the parent of the guest's process tree, like proot
 * with --kill-on-exit: when the program exits, or the launcher gets SIGTERM
 * (Process.destroy()), it kills what is left of the tree and exits with the
 * program's status.
 */

#include "burrow.h"

/* Removes envp[@index] from the stack the kernel built: the pointers after it,
 * up to the end of the auxiliary vector, move down one slot. */
static void remove_env(char** envp, long index) {
    long e = index;
    while (envp[e]) e++;
    uint64_t* auxv = (uint64_t*) (envp + e + 1);
    long a = 0;
    while (auxv[a] != 0) a += 2;
    char** end = (char**) (auxv + a + 2);
    memmove(envp + index, envp + index + 1, (char*) end - (char*) (envp + index + 1));
}

/* The host path of the open descriptor @fd, without symlinks. */
static long fd_path(long fd, char* out, long size) {
    char link[32] = "/proc/self/fd/";
    format_unsigned(link + 14, (unsigned long) fd);
    long n = sys(NR_readlinkat, AT_FDCWD, link, out, size - 1);
    if (n >= 0) out[n] = 0;
    return n;
}

static void add_bind(const char* spec) {
    if (cfg.bind_count == MAX_BINDS) die("too many bindings", 0);
    struct bind* b = &cfg.binds[cfg.bind_count++];
    long colon = 0;
    while (spec[colon] && spec[colon] != ':') colon++;
    if (colon >= (long) sizeof(b->host)) die("binding too long: ", spec);
    memcpy(b->host, spec, colon);
    b->host[colon] = 0;
    /* A relative host path is from the launcher's directory: made absolute, without symlinks. */
    if (b->host[0] != '/') {
        long fd = sys(NR_openat, AT_FDCWD, b->host, O_PATH | O_CLOEXEC, 0);
        if (fd < 0 || fd_path(fd, b->host, sizeof(b->host)) <= 0) die("cannot open the binding ", spec);
        sys(NR_close, fd, 0, 0, 0);
    }
    /* A relative guest path is from the guest's root. */
    const char* guest = spec[colon] ? spec + colon + 1 : spec;
    long slash = guest[0] != '/';
    if (slash) b->guest[0] = '/';
    long g = guest == spec ? colon : length_of(guest);
    if (slash + g >= (long) sizeof(b->guest)) die("binding too long: ", spec);
    memcpy(b->guest + slash, guest, g);
    b->guest[slash + g] = 0;
    b->host_length = length_of(b->host);
    b->guest_length = length_of(b->guest);
    /* "/dev/" and "/dev" are the same binding. */
    while (b->guest_length > 1 && b->guest[b->guest_length - 1] == '/') b->guest[--b->guest_length] = 0;
    while (b->host_length > 1 && b->host[b->host_length - 1] == '/') b->host[--b->host_length] = 0;
}

/* -- Supervisor ---------------------------------------------------------------- */

#define NR_getdents64 61
#define NR_kill 129
#define NR_clone 220
#define NR_wait4 260
#define SIGKILL 9
#define SIGCHLD 17
#define PR_SET_CHILD_SUBREAPER 36
#define MAX_PROCESSES 4096

static volatile int stop_requested;
static long main_child = -1;
static int main_status = -1; /* its wait status, once reaped */

static void reaped(long pid, int status) {
    if (pid == main_child) main_status = status;
}

static void on_stop(int sig) {
    (void) sig;
    stop_requested = 1;
}

/* The parent of process @pid, from /proc/<pid>/stat, or -1. */
static long parent_of(long pid) {
    char path[48] = "/proc/", buf[512];
    char* end = format_unsigned(path + 6, (unsigned long) pid);
    memcpy(end, "/stat", 6);
    long fd = sys(NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return -1;
    long n = sys(NR_read, fd, buf, sizeof(buf) - 1, 0);
    sys(NR_close, fd, 0, 0, 0);
    if (n <= 0) return -1;
    buf[n] = 0;
    /* "pid (comm) state ppid ...": comm may hold anything, ")" included. */
    long close_paren = -1;
    for (long i = 0; i < n; i++)
        if (buf[i] == ')') close_paren = i;
    if (close_paren < 0 || close_paren + 4 >= n) return -1;
    const char* p = buf + close_paren + 4;
    return (long) parse_unsigned(&p);
}

/* Kills every process below this one. Orphans come back to us as their
 * subreaper, so each one's chain of parents ends here. */
static void kill_tree(void) {
    static int pids[MAX_PROCESSES], parents[MAX_PROCESSES];
    static unsigned char mine[MAX_PROCESSES];
    long self = sys(NR_getpid, 0, 0, 0, 0);
    for (int round = 0; round < 100; round++) {
        long dir = sys(NR_openat, AT_FDCWD, "/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
        if (dir < 0) return;
        int count = 0;
        char entries[4096];
        long n;
        while ((n = sys(NR_getdents64, dir, entries, sizeof(entries), 0)) > 0) {
            for (long at = 0; at < n;) {
                uint16_t length = *(uint16_t*) (entries + at + 16);
                const char* name = entries + at + 19;
                at += length;
                if (name[0] < '1' || name[0] > '9' || count == MAX_PROCESSES) continue;
                long pid = (long) parse_unsigned(&name);
                long parent = parent_of(pid);
                if (parent < 0) continue;
                pids[count] = (int) pid;
                parents[count] = (int) parent;
                mine[count] = 0;
                count++;
            }
        }
        sys(NR_close, dir, 0, 0, 0);
        for (int changed = 1; changed;) {
            changed = 0;
            for (int i = 0; i < count; i++) {
                if (mine[i]) continue;
                int below = parents[i] == self;
                for (int j = 0; j < count && !below; j++) below = mine[j] && pids[j] == parents[i];
                if (below) mine[i] = 1, changed = 1;
            }
        }
        int killed = 0;
        for (int i = 0; i < count; i++)
            if (mine[i] && sys(NR_kill, pids[i], SIGKILL, 0, 0) == 0) killed++;
        int status;
        long pid;
        while ((pid = sys(NR_wait4, -1, &status, 1 /* WNOHANG */, 0)) > 0) reaped(pid, status);
        if (killed == 0) return;
    }
}

static __attribute__((noreturn)) void supervise(long child) {
    main_child = child;
    while (main_status < 0) {
        int status;
        long r = sys(NR_wait4, -1, &status, 0, 0);
        if (r > 0) reaped(r, status);
        else if (r == -EINTR && stop_requested) kill_tree();
        else if (r != -EINTR) break; /* ECHILD */
    }
    kill_tree();
    int s = main_status;
    int code = s < 0 ? 1 : (s & 0x7f) == 0 ? (s >> 8) & 0xff : 128 + (s & 0x7f);
    sys(NR_exit_group, code, 0, 0, 0);
    __builtin_unreachable();
}

static void launch(long argc, char** argv, char** envp) {
    const char* root = 0;
    const char* workdir = "/";
    long i = 1;
    for (; i < argc; i++) {
        const char* a = argv[i];
        if (same(a, "--")) {
            i++;
            break;
        }
        if (a[0] != '-') break;
        if (i + 1 >= argc) die("missing value for ", a);
        if (same(a, "-r")) root = argv[++i];
        else if (same(a, "-b")) add_bind(argv[++i]);
        else if (same(a, "-w")) workdir = argv[++i];
        else if (same(a, "-d")) {
            const char* p = argv[++i];
            unsigned long port = parse_unsigned(&p);
            if (*p || port == 0 || port > 65535) die("bad DNS port ", argv[i]);
            cfg.dns_port = (uint16_t) port;
        }
        else if (same(a, "-s")) {
            const char* p = argv[++i];
            if (p[0] != '/' || copy(cfg.stats, sizeof(cfg.stats), p) < 0) die("bad statistics file ", p);
        }
        else die("unknown option ", a);
    }
    if (root == 0 || i >= argc) die("usage: burrow -r ROOTFS [-b HOST[:GUEST]]... [-w DIR] [-d DNS_PORT] [-s STATS_FILE] PROGRAM [ARG]...", 0);

    long fd = sys(NR_openat, AT_FDCWD, root, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0 || (cfg.root_length = fd_path(fd, cfg.root, sizeof(cfg.root))) <= 1) die("cannot open the rootfs ", root);
    sys(NR_close, fd, 0, 0, 0);
    set_root_alias();
    if (sys(NR_readlinkat, AT_FDCWD, "/proc/self/exe", cfg.self, sizeof(cfg.self) - 1) <= 0)
        die("cannot find Burrow's own binary", 0);
    cfg.real_uid = (uint32_t) sys(NR_getuid, 0, 0, 0, 0);
    cfg.real_gid = (uint32_t) sys(NR_getgid, 0, 0, 0, 0);
    /* ids[] start at 0: the guest is root, in group root only. */
    cfg.group_count = 1;

    char host[PATH_MAX];
    long r = host_path(AT_FDCWD, workdir, 1, host);
    if (r < 0 || sys(NR_chdir, host, 0, 0, 0) < 0) die("cannot enter ", workdir);

    sys(NR_prctl, PR_SET_CHILD_SUBREAPER, 1, 0, 0);
    struct ksigaction stop = {(uintptr_t) on_stop, 0, 0, 0};
    const int stop_signals[] = {1 /* SIGHUP */, 2 /* SIGINT */, 15 /* SIGTERM */};
    for (int s = 0; s < 3; s++) sys(NR_rt_sigaction, stop_signals[s], &stop, 0, 8);
    long child = sys6(NR_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (child < 0) die("cannot fork", 0);
    if (child > 0) supervise(child);
    struct ksigaction dfl = {0, 0, 0, 0};
    for (int s = 0; s < 3; s++) sys(NR_rt_sigaction, stop_signals[s], &dfl, 0, 8);
    /* The app's blocked signals (SIGQUIT, SIGUSR1, SIGPIPE, 32: glibc's SIGCANCEL) are not the guest's. */
    uint64_t none = 0;
    sys(NR_rt_sigprocmask, 2 /* SIG_SETMASK */, &none, 0, 8);

    install_handler();
    r = install_filter();
    if (r < 0) die("cannot install the seccomp filter", 0);
    r = emulate_execve(AT_FDCWD, argv[i], argv + i, envp, 0);
    char number[24];
    format_unsigned(number, (unsigned long) -r);
    say("cannot execute ", argv[i], 0);
    die("errno ", number);
}

void burrow_main(long* sp) {
    long argc = sp[0];
    char** argv = (char**) (sp + 1);
    char** envp = argv + argc + 1;
    for (long e = 0; envp[e]; e++) {
        if (!starts_with(envp[e], "BURROW=")) continue;
        if (!decode_config(envp[e] + 7)) die("bad state in BURROW", 0);
        remove_env(envp, e);
        install_handler();
        load_and_run(sp);
    }
    launch(argc, argv, envp);
}
