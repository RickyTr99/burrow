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
#define NR_lseek 62
#define MFD_CLOEXEC 1
#define CLOCK_REALTIME 0
#define CLOCK_BOOTTIME 7

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
        put(t, " (droidnux@android) ");
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
    case 5: { /* stat: the CPUs and the boot time; their times are unknown */
        int cpus = cpu_count();
        put(t, "cpu  0 0 0 0 0 0 0 0 0 0\n");
        for (int i = 0; i < cpus; i++) {
            put(t, "cpu");
            put_number(t, (unsigned long) i);
            put(t, " 0 0 0 0 0 0 0 0 0 0\n");
        }
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
    }
}

static const char* const files[] = {
    "/proc/version", "/proc/sys/kernel/osrelease", "/proc/sys/kernel/hostname", "/proc/uptime", "/proc/loadavg",
    "/proc/stat", "/proc/sys/kernel/cap_last_cap", "/proc/sys/kernel/pid_max", "/proc/sys/fs/inotify/max_user_watches",
    "/proc/sys/fs/file-max", "/proc/sys/vm/overcommit_memory", "/proc/sys/kernel/shmmax", "/proc/swaps",
    "/proc/filesystems",
};

int proc_file(const char* host) {
    if (!starts_with(host, "/proc/")) return -1;
    for (unsigned i = 0; i < sizeof(files) / sizeof(*files); i++)
        if (same(host, files[i])) return (int) i;
    return -1;
}

long proc_open(int which, long flags) {
    if ((flags & 3) != O_RDONLY) return -EACCES;
    long fd = sys(NR_memfd_create, files[which] + 6, (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0, 0, 0);
    if (fd < 0) return fd;
    char buf[2048];
    struct text t = {buf, buf + sizeof(buf)};
    fill(which, &t);
    sys(NR_write, fd, buf, t.at - buf, 0);
    sys(NR_lseek, fd, 0, 0 /* SEEK_SET */, 0);
    return fd;
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
    o.fd = sys(NR_memfd_create, "maps", (flags & O_CLOEXEC) ? MFD_CLOEXEC : 0, 0, 0);
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
    sys(NR_close, in, 0, 0, 0);
    sys(NR_lseek, o.fd, 0, 0 /* SEEK_SET */, 0);
    return o.fd;
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
