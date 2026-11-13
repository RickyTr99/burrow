/*
 * Files of /proc that Android's SELinux policy refuses to apps, made up from
 * what the kernel still tells (uname, sysinfo, the clocks): when the real file
 * is refused, open() gets a memfd with the made-up content and stat() a
 * read-only regular file. LibreOffice does not start without /proc/version;
 * uptime, loadavg and stat feed top, ps and system monitors.
 */

#include "burrow.h"

#define NR_uname 160
#define NR_sysinfo 179
#define NR_clock_gettime 113
#define NR_sched_getaffinity 123
#define NR_memfd_create 279
#define NR_ftruncate 46
#define NR_pwrite64 68
#define MFD_CLOEXEC 1
#define CLOCK_REALTIME 0
#define CLOCK_BOOTTIME 7
#define O_RDWR 2
#define O_TMPFILE (020000000 | O_DIRECTORY)

struct utsname {
    char sysname[65], nodename[65], release[65], version[65], machine[65], domainname[65];
};

struct sysinfo {
    long uptime;
    unsigned long loads[3], totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    unsigned short procs, pad;
    unsigned long totalhigh, freehigh;
    unsigned int mem_unit;
    char reserved[256];
};

struct text {
    char* at;
    char* end;
};

static void put(struct text* t, const char* s) {
    while (*s && t->at < t->end) *t->at++ = *s++;
}

static void put_number(struct text* t, unsigned long v) {
    char digits[24];
    format_unsigned(digits, v);
    put(t, digits);
}

/* @v hundredths as "integer.hh". */
static void put_hundredths(struct text* t, unsigned long v) {
    put_number(t, v / 100);
    put(t, v % 100 < 10 ? ".0" : ".");
    put_number(t, v % 100);
}

static void uname_line(struct text* t, int field) {
    struct utsname u;
    if (sys(NR_uname, &u, 0, 0, 0) < 0) return;
    if (field == 0) {
        put(t, "Linux version ");
        put(t, u.release);
        put(t, " (burrow@android) ");
        put(t, u.version);
    } else {
        put(t, field == 1 ? u.release : u.nodename);
    }
    put(t, "\n");
}

static unsigned long seconds_of(int clock, unsigned long* hundredths) {
    long ts[2] = {0, 0};
    sys(NR_clock_gettime, clock, ts, 0, 0);
    if (hundredths) *hundredths = (unsigned long) ts[0] * 100 + (unsigned long) ts[1] / 10000000;
    return (unsigned long) ts[0];
}

static int cpu_count(void) {
    uint64_t mask[16] = {0};
    long n = sys(NR_sched_getaffinity, 0, sizeof(mask), mask, 0);
    int count = 0;
    for (long i = 0; i < n / 8; i++)
        for (uint64_t m = mask[i]; m; m &= m - 1) count++;
    return count > 0 ? count : 1;
}

/* /proc/stat's CPU times: Android refuses the real file, and shows an app
 * only its own processes. Each CPU gets what the app's threads ran on it
 * (their times since the last read, on the CPU they were last on), so the
 * counters only grow; the rest of the time is idle. Threads that end between
 * two reads lose their last slice. The state is the reading process's own. */

#define MAX_CPUS 64
#define THREADS 4096 /* slots, a power of two */

struct thread_time {
    int tid;
    unsigned long user, system;
};

static struct thread_time seen[2][THREADS]; /* the last read's threads, and this one's */
static int last_table;
static unsigned long cpu_user[MAX_CPUS], cpu_system[MAX_CPUS], cpu_idle[MAX_CPUS];
static int counting;

static struct thread_time* slot_of(struct thread_time* table, int tid, int add) {
    for (unsigned i = (unsigned) tid, n = 0; n < THREADS; i++, n++) {
        struct thread_time* s = &table[i & (THREADS - 1)];
        if (s->tid == tid) return s;
        if (s->tid == 0) {
            if (add) s->tid = tid;
            return add ? s : 0;
        }
    }
    return 0;
}

static char* append(char* to, const char* s) {
    while (*s) *to++ = *s++;
    *to = 0;
    return to;
}

/* utime, stime and processor (fields 14, 15 and 39) of a stat file. */
static int read_thread(const char* path, unsigned long* user, unsigned long* system, unsigned long* cpu) {
    char buf[1024];
    long fd = sys(NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 0;
    long n = sys(NR_read, fd, buf, sizeof(buf) - 1, 0);
    sys(NR_close, fd, 0, 0, 0);
    if (n <= 0) return 0;
    buf[n] = 0;
    const char* p = 0;
    for (long i = 0; i < n; i++)
        if (buf[i] == ')') p = buf + i + 1; /* the name may hold ')' */
    if (p == 0) return 0;
    for (int field = 3; field <= 39 && *p; field++) {
        while (*p == ' ') p++;
        if (field == 14) *user = parse_unsigned(&p);
        else if (field == 15) *system = parse_unsigned(&p);
        else if (field == 39) *cpu = parse_unsigned(&p);
        while (*p && *p != ' ') p++;
    }
    return 1;
}

/* Calls @each(path of a numbered entry) for each numbered entry of the directory @dir. */
static void numbered(const char* dir, void (*each)(char* path)) {
    long fd = sys(NR_openat, AT_FDCWD, dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char buf[4096], path[96];
    long n;
    while ((n = sys(NR_getdents64, fd, buf, sizeof(buf), 0)) > 0) {
        for (long at = 0; at < n;) {
            const char* name = buf + at + 19; /* d_ino, d_off, d_reclen, d_type */
            at += *(uint16_t*) (buf + at + 16);
            if (*name < '0' || *name > '9' || length_of(dir) + length_of(name) > 64) continue;
            append(append(append(path, dir), "/"), name);
            each(path);
        }
    }
    sys(NR_close, fd, 0, 0, 0);
}

static void count_thread(char* path) {
    unsigned long user = 0, system = 0, cpu = 0;
    append(path + length_of(path), "/stat");
    if (!read_thread(path, &user, &system, &cpu)) return;
    const char* id = path + length_of(path) - 5;
    while (id[-1] != '/') id--;
    int tid = (int) parse_unsigned(&id);
    struct thread_time* now = slot_of(seen[!last_table], tid, 1);
    if (now == 0) return; /* shortcut: past THREADS threads, the rest are not counted */
    now->user = user;
    now->system = system;
    struct thread_time* before = slot_of(seen[last_table], tid, 0);
    if (cpu >= MAX_CPUS) cpu = 0;
    if (before == 0) { /* a thread new since the last read: all of its time */
        cpu_user[cpu] += user;
        cpu_system[cpu] += system;
    } else {
        cpu_user[cpu] += user > before->user ? user - before->user : 0;
        cpu_system[cpu] += system > before->system ? system - before->system : 0;
    }
}

static void count_process(char* path) {
    append(path + length_of(path), "/task");
    numbered(path, count_thread);
}

/* @up: the time since boot in clock ticks (USER_HZ, 100 a second, as hundredths). */
static void count_cpu_times(unsigned long up) {
    if (__atomic_exchange_n(&counting, 1, __ATOMIC_ACQUIRE)) return; /* another thread is at it: its sums */
    memset(seen[!last_table], 0, sizeof(seen[0]));
    numbered("/proc", count_process);
    last_table = !last_table;
    for (int i = 0; i < MAX_CPUS; i++) {
        unsigned long busy = cpu_user[i] + cpu_system[i];
        if (up > busy && up - busy > cpu_idle[i]) cpu_idle[i] = up - busy;
    }
    __atomic_store_n(&counting, 0, __ATOMIC_RELEASE);
}

/* All the CPUs ("0-7"): the app's affinity changes as Android moves it between foreground and background. */
static int present_cpus(void) {
    char buf[64];
    long fd = sys(NR_openat, AT_FDCWD, "/sys/devices/system/cpu/present", O_RDONLY | O_CLOEXEC, 0);
    long n = fd < 0 ? 0 : sys(NR_read, fd, buf, sizeof(buf) - 1, 0);
    if (fd >= 0) sys(NR_close, fd, 0, 0, 0);
    if (n <= 0) return cpu_count() < MAX_CPUS ? cpu_count() : MAX_CPUS;
    buf[n] = 0;
    long last = n - 1;
    while (last > 0 && (buf[last] < '0' || buf[last] > '9')) last--;
    while (last > 0 && buf[last - 1] >= '0' && buf[last - 1] <= '9') last--;
    const char* p = buf + last;
    unsigned long cpus = parse_unsigned(&p) + 1;
    return cpus < MAX_CPUS ? (int) cpus : MAX_CPUS;
}

/* "cpuN user nice system idle iowait irq softirq steal guest guest_nice", @cpu -1 for the total. */
static void cpu_line(struct text* t, int cpu, unsigned long user, unsigned long system, unsigned long idle) {
    put(t, "cpu");
    if (cpu >= 0) put_number(t, (unsigned long) cpu);
    else put(t, " ");
    put(t, " ");
    put_number(t, user);
    put(t, " 0 ");
    put_number(t, system);
    put(t, " ");
    put_number(t, idle);
    put(t, " 0 0 0 0 0 0\n");
}

static void fill(int which, struct text* t) {
    switch (which) {
    case 0: uname_line(t, 0); break;
    case 1: uname_line(t, 1); break;
    case 2: uname_line(t, 2); break;
    case 3: { /* uptime: idle time unknown */
        unsigned long up;
        seconds_of(CLOCK_BOOTTIME, &up);
        put_hundredths(t, up);
        put(t, " 0.00\n");
        break;
    }
    case 4: { /* loadavg */
        struct sysinfo s;
        memset(&s, 0, sizeof(s));
        sys(NR_sysinfo, &s, 0, 0, 0);
        for (int i = 0; i < 3; i++) {
            put_hundredths(t, (s.loads[i] * 100 + 32768) >> 16);
            put(t, " ");
        }
        put(t, "1/");
        put_number(t, s.procs);
        put(t, " ");
        put_number(t, (unsigned long) sys(NR_getpid, 0, 0, 0, 0));
        put(t, "\n");
        break;
    }
    case 5: { /* stat: the CPUs, with the times of the app's own threads, and the boot time */
        int cpus = present_cpus();
        unsigned long up;
        seconds_of(CLOCK_BOOTTIME, &up);
        count_cpu_times(up);
        unsigned long user = 0, system = 0, idle = 0;
        for (int i = 0; i < cpus; i++) {
            user += cpu_user[i];
            system += cpu_system[i];
            idle += cpu_idle[i];
        }
        cpu_line(t, -1, user, system, idle);
        for (int i = 0; i < cpus; i++) cpu_line(t, i, cpu_user[i], cpu_system[i], cpu_idle[i]);
        put(t, "intr 0\nctxt 0\nbtime ");
        put_number(t, seconds_of(CLOCK_REALTIME, 0) - seconds_of(CLOCK_BOOTTIME, 0));
        put(t, "\nprocesses 0\nprocs_running 1\nprocs_blocked 0\nsoftirq 0\n");
        break;
    }
    case 6: put(t, "40\n"); break;                   /* sys/kernel/cap_last_cap */
    case 7: put(t, "4194304\n"); break;              /* sys/kernel/pid_max */
    case 8: put(t, "65536\n"); break;                /* sys/fs/inotify/max_user_watches */
    case 9: put(t, "9223372036854775807\n"); break;  /* sys/fs/file-max */
    case 10: put(t, "1\n"); break;                   /* sys/vm/overcommit_memory: Android's */
    case 11: put(t, "18446744073692774399\n"); break; /* sys/kernel/shmmax */
    case 12:
        put(t, "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n");
        break;
    case 13:
        put(t, "nodev\tsysfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tdevpts\nnodev\tfuse\n\text4\n\tf2fs\n\tvfat\n");
        break;
    case 14: /* sys/kernel/overflowuid: bwrap maps it in its user namespaces */
    case 15: put(t, "65534\n"); break; /* sys/kernel/overflowgid */
    }
}

static const char* const files[] = {
    "/proc/version", "/proc/sys/kernel/osrelease", "/proc/sys/kernel/hostname", "/proc/uptime", "/proc/loadavg",
    "/proc/stat", "/proc/sys/kernel/cap_last_cap", "/proc/sys/kernel/pid_max", "/proc/sys/fs/inotify/max_user_watches",
    "/proc/sys/fs/file-max", "/proc/sys/vm/overcommit_memory", "/proc/sys/kernel/shmmax", "/proc/swaps",
    "/proc/filesystems", "/proc/sys/kernel/overflowuid", "/proc/sys/kernel/overflowgid",
};

int proc_file(const char* host) {
    if (!starts_with(host, "/proc/")) return -1;
    for (unsigned i = 0; i < sizeof(files) / sizeof(*files); i++)
        if (same(host, files[i])) return (int) i;
    return -1;
}

#define MEMFD_PREFIX "burrow-proc-" /* then the file's index */

static void write_file(long fd, int which) {
    char buf[2048];
    struct text t = {buf, buf + sizeof(buf)};
    fill(which, &t);
    sys(NR_ftruncate, fd, 0, 0, 0);
    sys6(NR_pwrite64, fd, (long) buf, t.at - buf, 0, 0, 0);
}

long proc_open(int which, long flags) {
    if ((flags & 3) != O_RDONLY) return -EACCES;
    char name[32];
    format_unsigned(append(name, MEMFD_PREFIX), (unsigned long) which);
    long fd = sys(NR_memfd_create, name, (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0, 0, 0);
    if (fd < 0) return fd;
    write_file(fd, which);
    return fd;
}

/* Programs that keep /proc/stat open (top, ksystemstats) read it again from
 * the start: the content of a made-up file is made again then. */
void proc_rewind(long fd) {
    char target[64];
    if (fd_path(fd, target, sizeof(target)) <= 0) return;
    if (!starts_with(target, "/memfd:" MEMFD_PREFIX)) return;
    const char* p = target + 7 + sizeof(MEMFD_PREFIX) - 1;
    unsigned long which = parse_unsigned(&p);
    if (which < sizeof(files) / sizeof(*files)) write_file(fd, (int) which);
}

/* An unnamed file to write a rewritten /proc file in: in the rootfs' /tmp,
 * a memfd where O_TMPFILE fails. */
static long scratch(const char* name, long flags) {
    char tmp[PATH_MAX];
    if (cfg.root_length + 5 < PATH_MAX) {
        memcpy(tmp, cfg.root, cfg.root_length);
        memcpy(tmp + cfg.root_length, "/tmp", 5);
        long fd = sys(NR_openat, AT_FDCWD, tmp, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
        if (fd >= 0) return fd;
    }
    return sys(NR_memfd_create, name, (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0, 0, 0);
}

/* The filled @fd of scratch() as open() of the real file gives it: read-only,
 * at the start. Electron's main process stops on a writable descriptor of
 * /proc/<pid>/status (Chromium checks the access mode with F_GETFL). Android's
 * SELinux refuses reopening a memfd: that one stays writable. */
static long read_only(long fd, long flags) {
    char link[32] = "/proc/self/fd/";
    format_unsigned(link + 14, (unsigned long) fd);
    long r = sys(NR_openat, AT_FDCWD, link, O_RDONLY | (flags & O_CLOEXEC), 0);
    if (r < 0) {
        sys(NR_lseek, fd, 0, 0 /* SEEK_SET */, 0);
        return fd;
    }
    sys(NR_close, fd, 0, 0, 0);
    return r;
}

/* The /proc file each rewritten copy stands for, by the copy's inode (and
 * ctime, against a reused inode): readlink() of a descriptor's fd link names
 * that file, as for the real one. FEX recognizes the /proc files it emulates
 * by that name. A ring: a copy still open after 64 newer ones shows its own
 * path again. */
#define COPIES 64
static struct copy_of {
    uint64_t dev, ino;
    int64_t ctime[2];
    char path[56];
} copies[COPIES];
static unsigned copies_next;

/* Remembers that @copy stands for @in, the real file it was made from. */
static void remember_copy(long copy, long in) {
    char path[sizeof(copies->path)];
    long n = fd_path(in, path, sizeof(path));
    struct kstat st;
    if (n <= 0 || n >= (long) sizeof(path) - 1 || sys(NR_fstat, copy, &st, 0, 0) < 0) return;
    struct copy_of* c = &copies[__atomic_fetch_add(&copies_next, 1, __ATOMIC_RELAXED) % COPIES];
    __atomic_store_n(&c->ino, 0, __ATOMIC_RELEASE);
    c->dev = st.dev;
    c->ctime[0] = st.times[4];
    c->ctime[1] = st.times[5];
    memcpy(c->path, path, n + 1);
    __atomic_store_n(&c->ino, st.ino, __ATOMIC_RELEASE);
}

long proc_copy_target(const char* host, char* out) {
    struct kstat st;
    if (sys(NR_newfstatat, AT_FDCWD, host, &st, 0) < 0 || st.nlink != 0) return -1;
    for (int i = 0; i < COPIES; i++) {
        struct copy_of* c = &copies[i];
        if (__atomic_load_n(&c->ino, __ATOMIC_ACQUIRE) != st.ino || c->dev != st.dev || c->ctime[0] != st.times[4] ||
            c->ctime[1] != st.times[5])
            continue;
        char path[sizeof(c->path)];
        memcpy(path, c->path, sizeof(path));
        path[sizeof(path) - 1] = 0;
        if (__atomic_load_n(&c->ino, __ATOMIC_ACQUIRE) == st.ino) return copy(out, PATH_MAX, path);
    }
    return -1;
}

/* /proc/<pid>/maps names the rootfs' files by their host paths: their guest
 * paths instead (VLC finds its plugins from libvlccore's, gdb its libraries). */
int proc_maps(const char* host) {
    long n = length_of(host);
    return n > 11 && starts_with(host, "/proc/") && same(host + n - 5, "/maps");
}

struct output {
    long fd, used;
    char buf[8192];
};

static void out_put(struct output* o, const char* s, long n) {
    if (o->used + n > (long) sizeof(o->buf)) {
        sys(NR_write, o->fd, o->buf, o->used, 0);
        o->used = 0;
    }
    if (n > (long) sizeof(o->buf)) {
        sys(NR_write, o->fd, s, n, 0);
        return;
    }
    memcpy(o->buf + o->used, s, n);
    o->used += n;
}

/* One line of maps, its path (after the first '/': addresses have none) as the guest's. */
static void maps_line(struct output* o, char* line, long n, char* guest) {
    long at = 0;
    while (at < n && line[at] != '/') at++;
    out_put(o, line, at);
    if (at < n) {
        line[n] = 0;
        long g = host_to_guest(line + at, guest, PATH_MAX);
        if (g >= 0) out_put(o, guest, g);
        else out_put(o, line + at, n - at);
    }
    out_put(o, "\n", 1);
}

long proc_maps_open(const char* host, long flags) {
    if ((flags & 3) != O_RDONLY) return -EACCES;
    long in = sys(NR_openat, AT_FDCWD, host, O_RDONLY | O_CLOEXEC, 0);
    if (in < 0) return in;
    struct output o;
    o.used = 0;
    o.fd = scratch("maps", flags);
    if (o.fd < 0) {
        sys(NR_close, in, 0, 0, 0);
        return o.fd;
    }
    char buf[4096], line[PATH_MAX + 128], guest[PATH_MAX];
    long used = 0, n;
    while ((n = sys(NR_read, in, buf, sizeof(buf), 0)) > 0) {
        for (long i = 0; i < n; i++) {
            if (buf[i] == '\n') {
                maps_line(&o, line, used, guest);
                used = 0;
            } else if (used < (long) sizeof(line) - 1) {
                line[used++] = buf[i];
            }
        }
    }
    if (used > 0) maps_line(&o, line, used, guest);
    sys(NR_write, o.fd, o.buf, o.used, 0);
    remember_copy(o.fd, in);
    sys(NR_close, in, 0, 0, 0);
    return read_only(o.fd, flags);
}

/* /proc/<pid>/mounts and mountinfo list Android's mounts (the system's
 * erofs as /, apexes, vendor partitions): the guest's instead, as its own
 * root sees them. / is the mount holding the rootfs, each binding is a mount
 * at its guest path, and the host's mounts below a binding's source (/dev/pts,
 * /sys/fs/...) show below it. df, findmnt, Dolphin and bwrap read them. Every
 * process gets this process's bindings. */
int proc_mounts(const char* host) {
    long n = length_of(host);
    if (n < 12 || !starts_with(host, "/proc/")) return 0;
    if (same(host + n - 10, "/mountinfo")) return 2;
    return same(host + n - 7, "/mounts") ? 1 : 0;
}

struct host_mount {
    char *majmin, *root, *point, *options, *tail; /* tail: optional fields, "-", type, source, super options */
};

struct guest_mount {
    char guest[512];
    char root[512];
    struct host_mount* from;
    int parent;
};

#define HOST_TEXT (1 << 20)
#define MAX_MOUNTS 1024
#define MOUNTS_AREA (HOST_TEXT + MAX_MOUNTS * (sizeof(struct host_mount) + sizeof(struct guest_mount)))

/* Decodes mountinfo's octal escapes (\040) in place. */
static void unescape(char* s) {
    char* to = s;
    for (; *s; s++) {
        if (s[0] == '\\' && s[1] >= '0' && s[1] <= '3' && s[2] >= '0' && s[2] <= '7' && s[3] >= '0' && s[3] <= '7') {
            *to++ = (char) ((s[1] - '0') * 64 + (s[2] - '0') * 8 + (s[3] - '0'));
            s += 3;
        } else {
            *to++ = *s;
        }
    }
    *to = 0;
}

static void out_string(struct output* o, const char* s) {
    out_put(o, s, length_of(s));
}

/* @s with mountinfo's escapes for space, tab, newline and backslash. */
static void out_escaped(struct output* o, const char* s) {
    for (; *s; s++) {
        unsigned char c = (unsigned char) *s;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\\') {
            char e[4] = {'\\', (char) ('0' + (c >> 6)), (char) ('0' + ((c >> 3) & 7)), (char) ('0' + (c & 7))};
            out_put(o, e, 4);
        } else {
            out_put(o, s, 1);
        }
    }
}

/* Whether @path is @dir or below it. */
static int at_or_below(const char* path, const char* dir) {
    long n = length_of(dir);
    if (n == 1 && dir[0] == '/') return 1;
    return starts_with(path, dir) && (path[n] == 0 || path[n] == '/');
}

/* Splits the host's mountinfo in @text into @mounts; their count. */
static int parse_mounts(char* text, struct host_mount* mounts) {
    int count = 0;
    for (char* line = text; *line && count < MAX_MOUNTS;) {
        char* end = line;
        while (*end && *end != '\n') end++;
        char* next = *end ? end + 1 : end;
        *end = 0;
        char* field[6];
        char* p = line;
        int f = 0;
        for (; f < 6 && *p; f++) { /* id, parent, major:minor, root, mount point, options */
            field[f] = p;
            while (*p && *p != ' ') p++;
            if (*p) *p++ = 0;
        }
        if (f == 6 && *p) {
            struct host_mount* m = &mounts[count++];
            m->majmin = field[2];
            m->root = field[3];
            m->point = field[4];
            m->options = field[5];
            m->tail = p;
            unescape(m->root);
            unescape(m->point);
        }
        line = next;
    }
    return count;
}

/* The mount @host is on: the deepest mount point above it, the last mounted of equals. */
static struct host_mount* mount_of(struct host_mount* mounts, int count, const char* host) {
    struct host_mount* best = 0;
    long best_length = -1;
    for (int i = 0; i < count; i++) {
        long n = length_of(mounts[i].point);
        if (n >= best_length && at_or_below(host, mounts[i].point)) {
            best = &mounts[i];
            best_length = n;
        }
    }
    return best;
}

/* Adds @guest, from @from at @root below its own root; the new count. */
static int add_mount(struct guest_mount* out, int count, const char* guest, struct host_mount* from, const char* root) {
    if (count >= MAX_MOUNTS) return count;
    struct guest_mount* g = &out[count];
    long base = same(from->root, "/") ? 0 : length_of(from->root);
    if (length_of(guest) >= (long) sizeof(g->guest) || base + length_of(root) >= (long) sizeof(g->root)) return count;
    append(g->guest, guest);
    memcpy(g->root, from->root, base);
    append(g->root + base, *root ? root : base ? "" : "/");
    g->from = from;
    return count + 1;
}

/* Android's own mounts below /dev: binder, USB gadgets, cgroup v1 controllers. */
static int android_only(const struct host_mount* m) {
    static const char* const types[] = {"- binder ", "- functionfs ", "- cgroup "};
    for (unsigned i = 0; i < sizeof(types) / sizeof(*types); i++)
        for (const char* p = m->tail; *p; p++)
            if (starts_with(p, types[i])) return 1;
    return 0;
}

/* Whether a binding deeper than @self covers @guest. */
static int covered(const char* guest, int self) {
    for (int i = 0; i < cfg.bind_count; i++)
        if (cfg.binds[i].guest_length > cfg.binds[self].guest_length && at_or_below(guest, cfg.binds[i].guest))
            return 1;
    return 0;
}

/* The type, source and super options of a mount's @tail (cut in place). */
static int tail_fields(char* tail, char** type, char** source, char** super) {
    char* p = tail;
    while (*p && !(p[0] == '-' && (p == tail || p[-1] == ' ') && p[1] == ' ')) p++;
    if (!*p) return 0;
    p += 2;
    *type = p;
    while (*p && *p != ' ') p++;
    if (!*p) return 0;
    *p++ = 0;
    *source = p;
    while (*p && *p != ' ') p++;
    if (*p) *p++ = 0;
    *super = p;
    return 1;
}

static void out_number(struct output* o, unsigned long v) {
    char number[24];
    format_unsigned(number, v);
    out_string(o, number);
}

static void write_mounts(struct output* o, struct guest_mount* out, int count, int info) {
    for (int i = 0; i < count; i++) {
        struct guest_mount* g = &out[i];
        char tail[1024];
        if (copy(tail, sizeof(tail), g->from->tail) < 0) continue;
        if (info) {
            out_number(o, (unsigned long) (20 + i));
            out_string(o, " ");
            out_number(o, (unsigned long) (g->parent < 0 ? 1 : 20 + g->parent));
            out_string(o, " ");
            out_string(o, g->from->majmin);
            out_string(o, " ");
            out_escaped(o, g->root);
            out_string(o, " ");
            out_escaped(o, g->guest);
            out_string(o, " ");
            out_string(o, g->from->options);
            out_string(o, " ");
            out_string(o, tail);
        } else {
            char *type, *source, *super;
            if (!tail_fields(tail, &type, &source, &super)) continue;
            out_string(o, source);
            out_string(o, " ");
            out_escaped(o, g->guest);
            out_string(o, " ");
            out_string(o, type);
            out_string(o, " ");
            out_string(o, g->from->options);
            /* The super options after their rw or ro, as the kernel lists both. */
            while (*super && *super != ',') super++;
            out_string(o, super);
            out_string(o, " 0 0");
        }
        out_string(o, "\n");
    }
}

/* The guest's mounts from the host's @mounts into @out: / first, then each binding and the host's mounts below it. */
static int guest_mounts(struct host_mount* mounts, int hosts, struct guest_mount* out) {
    struct host_mount* root = mount_of(mounts, hosts, cfg.root);
    if (root == 0) return 0;
    int count = add_mount(out, 0, "/", root, "/");
    if (count) memcpy(out[0].root, "/", 2); /* the guest's root is the whole of it */
    for (int b = 0; b < cfg.bind_count; b++) {
        struct bind* bind = &cfg.binds[b];
        struct host_mount* m = mount_of(mounts, hosts, bind->host);
        if (m == 0) continue;
        /* From the rootfs, it is below the guest's / (findmnt's "[/tmp/x]"). */
        if (count && at_or_below(bind->host, cfg.root) && bind->host_length > cfg.root_length)
            count = add_mount(out, count, bind->guest, out[0].from, bind->host + cfg.root_length);
        else
            count = add_mount(out, count, bind->guest, m, same(m->point, "/") ? bind->host : bind->host + length_of(m->point));
        if (bind->walked) continue;
        for (int i = 0; i < hosts; i++) {
            const char* point = mounts[i].point;
            if (same(point, bind->host) || !at_or_below(point, bind->host)) continue;
            if (android_only(&mounts[i])) continue;
            char guest[512];
            const char* rest = point + bind->host_length;
            if (bind->guest_length + length_of(rest) >= (long) sizeof(guest)) continue;
            append(append(guest, bind->guest), rest);
            if (!covered(guest, b)) count = add_mount(out, count, guest, &mounts[i], "");
        }
    }
    /* Each mount's parent: the deepest one above it, or an earlier one at the same place. */
    for (int i = 0; i < count; i++) {
        long length = length_of(out[i].guest), best = -1;
        out[i].parent = -1;
        for (int j = 0; j < count; j++) {
            long n = length_of(out[j].guest);
            if (j == i || n <= best || !at_or_below(out[i].guest, out[j].guest) || (n == length && j > i)) continue;
            out[i].parent = j;
            best = n;
        }
        if (i == 0) out[i].parent = -1;
    }
    return count;
}

long proc_mounts_open(const char* host, long flags) {
    if ((flags & 3) != O_RDONLY) return -EACCES;
    long in = sys(NR_openat, AT_FDCWD, host, O_RDONLY | O_CLOEXEC, 0);
    if (in < 0) return in;
    long info = sys(NR_openat, AT_FDCWD, "/proc/self/mountinfo", O_RDONLY | O_CLOEXEC, 0);
    char* area = (char*) sys6(NR_mmap, 0, MOUNTS_AREA, 3 /* PROT_READ | PROT_WRITE */,
                              0x22 /* MAP_PRIVATE | MAP_ANONYMOUS */, -1, 0);
    long error = info < 0 ? info : (unsigned long) area > -4096UL ? (long) area : 0;
    if (error) {
        if (info >= 0) sys(NR_close, info, 0, 0, 0);
        else sys(NR_munmap, area, MOUNTS_AREA, 0, 0);
        sys(NR_close, in, 0, 0, 0);
        return error;
    }
    long used = 0, n;
    while (used < HOST_TEXT - 1 && (n = sys(NR_read, info, area + used, HOST_TEXT - 1 - used, 0)) > 0) used += n;
    sys(NR_close, info, 0, 0, 0);
    area[used] = 0;
    struct host_mount* mounts = (struct host_mount*) (area + HOST_TEXT);
    struct guest_mount* out = (struct guest_mount*) (mounts + MAX_MOUNTS);
    int count = guest_mounts(mounts, parse_mounts(area, mounts), out);
    struct output o;
    o.used = 0;
    o.fd = scratch("mounts", flags);
    if (o.fd >= 0) {
        write_mounts(&o, out, count, proc_mounts(host) == 2);
        sys(NR_write, o.fd, o.buf, o.used, 0);
        remember_copy(o.fd, in);
    }
    sys(NR_munmap, area, MOUNTS_AREA, 0, 0);
    sys(NR_close, in, 0, 0, 0);
    return o.fd < 0 ? o.fd : read_only(o.fd, flags);
}

/* /proc/<pid>/status has the app's uid and gid: the guest's instead, as
 * fake_owner() shows files (ps's user, "own processes" of system monitors). */
int proc_status(const char* host) {
    long n = length_of(host);
    return n > 13 && starts_with(host, "/proc/") && same(host + n - 7, "/status");
}

/* "Uid:" or "Gid:" and its real, effective, saved and file system ids, @base RUID or RGID. */
static void ids_line(struct text* t, const char** p, int base, uint32_t real) {
    put(t, base == RUID ? "Uid:" : "Gid:");
    for (int i = 0; i < 4; i++) {
        while (**p == '\t' || **p == ' ') (*p)++;
        unsigned long v = parse_unsigned(p);
        put(t, "\t");
        put_number(t, v == real ? __atomic_load_n(&cfg.ids[base + i], __ATOMIC_RELAXED) : v);
    }
}

long proc_status_open(const char* host, long flags) {
    if ((flags & 3) != O_RDONLY) return -EACCES;
    long in = sys(NR_openat, AT_FDCWD, host, O_RDONLY | O_CLOEXEC, 0);
    if (in < 0) return in;
    char raw[8192], out[8192 + 64];
    long n = 0, r;
    while (n < (long) sizeof(raw) - 1 && (r = sys(NR_read, in, raw + n, sizeof(raw) - 1 - n, 0)) > 0) n += r;
    raw[n] = 0;
    struct text t = {out, out + sizeof(out)};
    for (const char* p = raw; *p;) {
        if (starts_with(p, "Uid:") || starts_with(p, "Gid:")) {
            int base = *p == 'U' ? RUID : RGID;
            p += 4;
            ids_line(&t, &p, base, base == RUID ? cfg.real_uid : cfg.real_gid);
            while (*p && *p != '\n') p++;
        }
        const char* line = p;
        while (*p && *p != '\n') p++;
        if (*p) p++;
        while (line < p && t.at < t.end) *t.at++ = *line++;
    }
    long fd = scratch("status", flags);
    if (fd >= 0) {
        sys(NR_write, fd, out, t.at - out, 0);
        remember_copy(fd, in);
    }
    sys(NR_close, in, 0, 0, 0);
    return fd < 0 ? fd : read_only(fd, flags);
}

/* /proc's files show as empty, read-only and root's. */
long proc_stat(struct kstat* st) {
    long fd = sys(NR_memfd_create, "stat", MFD_CLOEXEC, 0, 0);
    if (fd < 0) return fd;
    long r = sys(NR_fstat, fd, st, 0, 0);
    sys(NR_close, fd, 0, 0, 0);
    if (r < 0) return r;
    st->mode = S_IFREG | 0444;
    st->uid = st->gid = 0;
    return 0;
}

long proc_statx(struct kstatx* stx) {
    long fd = sys(NR_memfd_create, "stat", MFD_CLOEXEC, 0, 0);
    if (fd < 0) return fd;
    long r = sys6(NR_statx, fd, (long) "", AT_EMPTY_PATH, 0xfff /* STATX_BASIC_STATS */, (long) stx, 0);
    sys(NR_close, fd, 0, 0, 0);
    if (r < 0) return r;
    stx->mode = (uint16_t) (S_IFREG | 0444);
    stx->uid = stx->gid = 0;
    return 0;
}

/* /proc/<pid>/auxv is the kernel's, for Burrow's binary: its entry, its
 * program headers, no interpreter (gdb found no libraries and no backtrace).
 * The guest's instead, which the loader left on the process's stack; the
 * kernel's for a process with no program loaded (the launcher). */
int proc_auxv(const char* host) {
    long n = length_of(host);
    return n > 10 && starts_with(host, "/proc/") && same(host + n - 5, "/auxv");
}

#define AUXV_WORDS 256

/* The auxiliary vector of the process of @path (after "/proc/") into @out, with its AT_NULL; its size or 0. */
static long guest_auxv(const char* path, uint64_t* out) {
    long n;
    if (starts_with(path, "self/") || starts_with(path, "thread-self/")) {
        if (cfg.auxv == 0) return 0;
        /* Pair by pair: the stack may end soon after the vector. */
        for (n = 0; n < AUXV_WORDS; n += 2) {
            out[n] = cfg.auxv[n], out[n + 1] = cfg.auxv[n + 1];
            if (out[n] == 0) return (n + 2) * 8;
        }
        return 0;
    }
    const char* p = path;
    long pid = (long) parse_unsigned(&p);
    uint64_t* remote = 0;
    if (p == path || *p != '/' || peer_read(pid, &remote, &cfg.auxv, sizeof(remote)) != sizeof(remote) || remote == 0)
        return 0;
    /* A read stopped by the end of the stack is short, not failed. */
    n = peer_read(pid, out, remote, AUXV_WORDS * 8) / 8;
    for (long i = 0; i + 1 < n; i += 2)
        if (out[i] == 0) return (i + 2) * 8;
    return 0;
}

long proc_auxv_open(const char* host, long flags) {
    uint64_t auxv[AUXV_WORDS];
    long size = (flags & 3) == O_RDONLY ? guest_auxv(host + 6, auxv) : 0;
    if (size == 0) return sys(NR_openat, AT_FDCWD, host, flags, 0);
    long in = sys(NR_openat, AT_FDCWD, host, O_RDONLY | O_CLOEXEC, 0);
    if (in < 0) return in;
    long fd = scratch("auxv", flags);
    if (fd >= 0) {
        sys(NR_write, fd, auxv, size, 0);
        remember_copy(fd, in);
    }
    sys(NR_close, in, 0, 0, 0);
    return fd < 0 ? fd : read_only(fd, flags);
}
