/*
 * Entry point: the loader of an emulated execve() when BURROW is in the
 * environment, the launcher otherwise:
 *
 *   libburrow.so -r ROOTFS [-b HOST[:GUEST]]... [-w GUEST_DIR] [--] PROGRAM [ARG]...
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

static void add_bind(const char* spec) {
    if (cfg.bind_count == MAX_BINDS) die("too many bindings", 0);
    struct bind* b = &cfg.binds[cfg.bind_count++];
    long colon = 0;
    while (spec[colon] && spec[colon] != ':') colon++;
    if (colon >= (long) sizeof(b->host)) die("binding too long: ", spec);
    memcpy(b->host, spec, colon);
    b->host[colon] = 0;
    if (copy(b->guest, sizeof(b->guest), spec[colon] ? spec + colon + 1 : b->host) < 0)
        die("binding too long: ", spec);
    b->host_length = length_of(b->host);
    b->guest_length = length_of(b->guest);
    /* "/dev/" and "/dev" are the same binding. */
    while (b->guest_length > 1 && b->guest[b->guest_length - 1] == '/') b->guest[--b->guest_length] = 0;
    while (b->host_length > 1 && b->host[b->host_length - 1] == '/') b->host[--b->host_length] = 0;
}

/* The host path of the open descriptor @fd, without symlinks. */
static long fd_path(long fd, char* out, long size) {
    char link[32] = "/proc/self/fd/";
    format_unsigned(link + 14, (unsigned long) fd);
    long n = sys(NR_readlinkat, AT_FDCWD, link, out, size - 1);
    if (n >= 0) out[n] = 0;
    return n;
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
        else die("unknown option ", a);
    }
    if (root == 0 || i >= argc) die("usage: libburrow.so -r ROOTFS [-b HOST[:GUEST]]... [-w DIR] PROGRAM [ARG]...", 0);

    long fd = sys(NR_openat, AT_FDCWD, root, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0 || (cfg.root_length = fd_path(fd, cfg.root, sizeof(cfg.root))) <= 1) die("cannot open the rootfs ", root);
    sys(NR_close, fd, 0, 0, 0);
    set_root_alias();
    if (sys(NR_readlinkat, AT_FDCWD, "/proc/self/exe", cfg.self, sizeof(cfg.self) - 1) <= 0)
        die("cannot find Burrow's own binary", 0);
    cfg.real_uid = (uint32_t) sys(NR_getuid, 0, 0, 0, 0);
    cfg.real_gid = (uint32_t) sys(NR_getgid, 0, 0, 0, 0);
    /* ids[] start at 0: the guest is root. */

    char host[PATH_MAX];
    long r = host_path(AT_FDCWD, workdir, 1, host);
    if (r < 0 || sys(NR_chdir, host, 0, 0, 0) < 0) die("cannot enter ", workdir);

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
