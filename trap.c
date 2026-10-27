/*
 * The seccomp filter and the SIGSYS handler that emulates the trapped
 * syscalls in the guest process.
 *
 * The handler runs on the trapping thread with the syscall's registers in the
 * signal frame: it makes the real syscalls through the gadget and writes the
 * result into x0. The kernel resets a blocked or ignored SIGSYS to the
 * default action (death) before delivering a trap, so the guest never gets to
 * block it: masks are filtered and the guest's own SIGSYS disposition is only
 * recorded (its handler gets the traps of its own filters).
 */

#include "burrow.h"

extern char burrow_gadget[];

/* -- The filter --------------------------------------------------------------------- */

static const uint16_t trapped[] = {
    NR_setxattr, NR_lsetxattr, NR_getxattr, NR_lgetxattr, NR_listxattr, NR_llistxattr, NR_removexattr,
    NR_lremovexattr, NR_getcwd, NR_inotify_add_watch, NR_mknodat, NR_mkdirat, NR_unlinkat, NR_symlinkat,
    NR_linkat, NR_renameat, NR_statfs, NR_truncate, NR_faccessat, NR_chdir, NR_fchmodat, NR_fchownat, NR_fchown,
    NR_openat, NR_readlinkat, NR_newfstatat, NR_fstat, NR_utimensat, NR_rt_sigaction, NR_rt_sigprocmask,
    NR_setregid, NR_setgid, NR_setreuid, NR_setuid, NR_setresuid, NR_getresuid, NR_setresgid, NR_getresgid,
    NR_setfsuid, NR_setfsgid, NR_getgroups, NR_setgroups, NR_getuid, NR_geteuid, NR_getgid, NR_getegid, NR_bind, NR_connect,
    NR_execve, NR_renameat2, NR_execveat, NR_statx, NR_openat2, NR_faccessat2, NR_fchmodat2, NR_sendmsg,
    NR_sendto, NR_recvfrom, NR_getsockname, NR_getpeername, NR_shmget, NR_shmctl, NR_shmat, NR_shmdt, NR_chroot,
    NR_clone3, /* ENOSYS, as under Android: CLONE_CLEAR_SIGHAND would drop our handler */
};

struct sock_filter {
    uint16_t code;
    uint8_t jt, jf;
    uint32_t k;
};

#define LD_ABS 0x20 /* BPF_LD | BPF_W | BPF_ABS */
#define JEQ 0x15    /* BPF_JMP | BPF_JEQ | BPF_K */
#define RET 0x06    /* BPF_RET | BPF_K */
#define RET_ALLOW 0x7fff0000u
#define RET_TRAP 0x00030000u
#define RET_ERRNO 0x00050000u
#define AUDIT_ARCH_AARCH64 0xc00000b7u
#define DRM_IOCTL_VERSION 0xc0406400u
#define N_TRAPPED (sizeof(trapped) / sizeof(*trapped))

long install_filter(void) {
    uint64_t gadget = (uint64_t) burrow_gadget;
    struct sock_filter f[10 + N_TRAPPED + 31];
    int i = 0;
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 4}; /* arch */
    f[i++] = (struct sock_filter){JEQ, 1, 0, AUDIT_ARCH_AARCH64};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 12}; /* instruction pointer, high half */
    f[i++] = (struct sock_filter){JEQ, 0, 4, (uint32_t) (gadget >> 32)};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 8};
    f[i++] = (struct sock_filter){JEQ, 1, 0, (uint32_t) gadget + 4};
    f[i++] = (struct sock_filter){JEQ, 0, 1, (uint32_t) gadget};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 0}; /* nr */
    for (unsigned t = 0; t < N_TRAPPED; t++)
        f[i++] = (struct sock_filter){JEQ, (uint8_t) (N_TRAPPED - t + 1), 0, trapped[t]};
    /* getsockopt(), only for SO_PEERCRED: the ids it reports are real. */
    f[i++] = (struct sock_filter){JEQ, 2, 6, NR_getsockopt};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW}; /* unused: keeps the jumps above to RET_TRAP */
    f[i++] = (struct sock_filter){RET, 0, 0, RET_TRAP | TRAP_DATA};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 1, 17 /* SO_PEERCRED */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_TRAP | TRAP_DATA};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* lseek(fd, 0, SEEK_SET) only: made-up /proc files read again (proc_rewind()). */
    f[i++] = (struct sock_filter){JEQ, 0, 6, NR_lseek};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 24}; /* args[1], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 3, 0};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 1, 0 /* SEEK_SET */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_TRAP | TRAP_DATA};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* socket(AF_NETLINK, *, NETLINK_AUDIT): SELinux says EACCES, which PAM
     * takes for a broken audit system (su and sudo fail); a kernel without
     * audit says EPROTONOSUPPORT. */
    f[i++] = (struct sock_filter){JEQ, 0, 6, NR_socket};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 16}; /* args[0], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 2, 16 /* AF_NETLINK */};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 32}; /* args[2], low half */
    f[i++] = (struct sock_filter){JEQ, 1, 0, 9 /* NETLINK_AUDIT */};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ERRNO | 93 /* EPROTONOSUPPORT */};
    /* prctl(PR_SET_KEEPCAPS) succeeds: Android locks the bit (ping keeps
     * capabilities across setuid()), and the guest's capabilities are fake. */
    f[i++] = (struct sock_filter){JEQ, 0, 4, NR_prctl};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 16}; /* args[0], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 1, PR_SET_KEEPCAPS};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ERRNO | 0};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    /* ioctl(DRM_IOCTL_VERSION) only: the render node is KGSL, see do_drm_version(). */
    f[i++] = (struct sock_filter){JEQ, 0, 3, NR_ioctl};
    f[i++] = (struct sock_filter){LD_ABS, 0, 0, 24}; /* args[1], low half */
    f[i++] = (struct sock_filter){JEQ, 0, 1, DRM_IOCTL_VERSION};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_TRAP | TRAP_DATA};
    f[i++] = (struct sock_filter){RET, 0, 0, RET_ALLOW};
    struct {
        unsigned short len;
        struct sock_filter* filter;
    } prog = {(unsigned short) i, f};
    long r = sys(NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0);
    if (r < 0) return r;
    return sys(NR_seccomp, 1 /* SECCOMP_SET_MODE_FILTER */, 0, &prog, 0);
}

/* -- Ids (proot's fake_id0) ------------------------------------------------------------ */

static uint32_t id(int which) { return __atomic_load_n(&cfg.ids[which], __ATOMIC_RELAXED); }
static void set_id(int which, uint32_t value) { __atomic_store_n(&cfg.ids[which], value, __ATOMIC_RELAXED); }

/* Files the app owns show as the saved set-ids': root until a program drops
 * its ids (apt's _apt then finds its own files). */
static void fake_owner(uint32_t* uid, uint32_t* gid) {
    if (*uid == cfg.real_uid) *uid = id(SUID);
    if (*gid == cfg.real_gid) *gid = id(SGID);
}

static int one_of(uint32_t v, int base) { return v == id(base) || v == id(base + 1) || v == id(base + 2); }

/* setuid() and friends, @base RUID or RGID. -1 leaves an id as it is. */
static long set_ids(int base, uint32_t r, uint32_t e, uint32_t s, int kind) {
    int privileged = id(EUID) == 0;
    uint32_t none = (uint32_t) -1;
    if (kind == 1) { /* setuid */
        if (privileged) {
            set_id(base, r), set_id(base + 1, r), set_id(base + 2, r), set_id(base + 3, r);
        } else if (r == id(base) || r == id(base + 2)) {
            set_id(base + 1, r), set_id(base + 3, r);
        } else {
            return -EPERM;
        }
        return 0;
    }
    if (!privileged) {
        if (r != none && !one_of(r, base)) return -EPERM;
        if (e != none && !one_of(e, base)) return -EPERM;
        if (s != none && !one_of(s, base)) return -EPERM;
    }
    uint32_t old_r = id(base);
    if (r != none) set_id(base, r);
    if (e != none) set_id(base + 1, e);
    if (kind == 2) { /* setreuid: the saved id follows a new effective one */
        if (r != none || (e != none && e != old_r)) set_id(base + 2, id(base + 1));
    } else if (s != none) {
        set_id(base + 2, s);
    }
    set_id(base + 3, id(base + 1));
    return 0;
}

static long get_ids(int base, uint32_t* r, uint32_t* e, uint32_t* s) {
    *r = id(base);
    *e = id(base + 1);
    *s = id(base + 2);
    return 0;
}

static long set_fs_id(int base, uint32_t v) {
    uint32_t old = id(base + 3);
    if (id(EUID) == 0 || one_of(v, base) || v == old) set_id(base + 3, v);
    return old;
}

/* -- Signals ------------------------------------------------------------------------- */

static struct ksigaction guest_sigsys; /* the guest's SIGSYS disposition */

#define SIGSYS_BIT (1ull << (SIGSYS - 1))

static long do_sigaction(long sig, const struct ksigaction* act, struct ksigaction* old, long size) {
    if (sig == SIGSYS) {
        struct ksigaction previous = guest_sigsys;
        if (act != 0) guest_sigsys = *act;
        if (old != 0) *old = previous;
        return 0;
    }
    struct ksigaction mine;
    if (act != 0) {
        mine = *act;
        mine.mask &= ~SIGSYS_BIT;
        act = &mine;
    }
    return sys(NR_rt_sigaction, sig, act, old, size);
}

/* The handler's return restores the mask saved in the signal frame, @mask:
 * the change goes there (to the thread, it would be undone). */
static long do_sigprocmask(uint64_t* mask, long how, const uint64_t* set, uint64_t* old, long size) {
    if (size != 8) return -EINVAL;
    uint64_t now = *mask;
    if (set != 0) {
        if (how == 0 /* SIG_BLOCK */) now |= *set;
        else if (how == 1 /* SIG_UNBLOCK */) now &= ~*set;
        else if (how == 2 /* SIG_SETMASK */) now = *set;
        else return -EINVAL;
        now &= ~(SIGSYS_BIT | 1ull << (9 - 1) /* SIGKILL */ | 1ull << (19 - 1) /* SIGSTOP */);
    }
    if (old != 0) *old = *mask;
    *mask = now;
    return 0;
}

/* A SIGSYS that is not ours: the guest's own filters (Firefox's sandbox),
 * Android's, or a kill(). */
static void foreign(int sig, struct ksiginfo* info, struct kucontext* uc) {
    uintptr_t h = guest_sigsys.handler;
    if (info->code == SYS_SECCOMP && info->errno_ == 0) {
        /* Android's app policy traps with a bare SECCOMP_RET_TRAP. */
        uint64_t* x = uc->mcontext.regs;
        switch (info->syscall) {
        case 202: /* accept: apps must use accept4 (Xwayland does not) */
            x[0] = (uint64_t) sys(242 /* accept4 */, x[0], x[1], x[2], 0);
            break;
        case 39:  /* umount2 */
        case 40:  /* mount */
        case 41:  /* pivot_root */
        case 97:  /* unshare */
        case 268: /* setns: as proot, pretend (sandbox helpers carry on) */
            x[0] = 0;
            break;
        default: /* clone3 (glibc falls back to clone), SysV semaphores and queues... */
            x[0] = (uint64_t) -ENOSYS;
        }
    } else if (h > 1) {
        if (guest_sigsys.flags & SA_SIGINFO) {
            ((void (*)(int, struct ksiginfo*, struct kucontext*)) h)(sig, info, uc);
        } else {
            ((void (*)(int)) h)(sig);
        }
    } else if (info->code == SYS_SECCOMP) {
        uc->mcontext.regs[0] = (uint64_t) -ENOSYS;
    } else if (h == 0) {
        /* The default action: die by it. */
        struct ksigaction dfl = {0, 0, 0, 0};
        sys(NR_rt_sigaction, SIGSYS, &dfl, 0, 8);
        sys(NR_tgkill, sys(NR_getpid, 0, 0, 0, 0), sys(NR_gettid, 0, 0, 0, 0), SIGSYS, 0);
    }
}

/* -- Path syscalls ---------------------------------------------------------------------- */

/* Android's shared storage, where the app may do anything with every file
 * (all-files access): its files show as the guest's own, else KIO marks
 * those of other apps unreadable. Its device, found once per process. */
static int on_shared_storage(uint32_t major, uint32_t minor) {
    static uint64_t device = 0; /* major << 32 | minor, 1 if none */
    if (device == 0) {
        struct kstat st;
        uint64_t d = 1;
        if (sys(NR_newfstatat, AT_FDCWD, "/storage/emulated/0", &st, 0) == 0)
            d = (uint64_t) ((st.dev >> 8) & 0xfff) << 32 | ((st.dev & 0xff) | ((st.dev >> 12) & 0xfff00));
        __atomic_store_n(&device, d, __ATOMIC_RELAXED);
    }
    return __atomic_load_n(&device, __ATOMIC_RELAXED) == ((uint64_t) major << 32 | minor);
}

static void fake_stat(long r, struct kstat* st) {
    if (r != 0) return;
    if (on_shared_storage((st->dev >> 8) & 0xfff, (st->dev & 0xff) | ((st->dev >> 12) & 0xfff00)))
        st->uid = cfg.real_uid, st->gid = cfg.real_gid;
    fake_owner(&st->uid, &st->gid);
}

static void fake_statx(long r, struct kstatx* stx) {
    if (r != 0) return;
    uint32_t uid = (stx->mask & STATX_UID) ? stx->uid : ~0u;
    uint32_t gid = (stx->mask & STATX_GID) ? stx->gid : ~0u;
    if (on_shared_storage(stx->dev_major, stx->dev_minor)) uid = cfg.real_uid, gid = cfg.real_gid;
    fake_owner(&uid, &gid);
    if (stx->mask & STATX_UID) stx->uid = uid;
    if (stx->mask & STATX_GID) stx->gid = gid;
}

/* An *at() syscall on the path (@dirfd, @path) with its host path instead. */
#define ON_HOST(follow, call)                                    \
    do {                                                         \
        char host[PATH_MAX];                                     \
        long r_ = host_path(dirfd, path, (follow), host);        \
        return r_ < 0 ? r_ : (call);                             \
    } while (0)

static int empty(const char* path) { return path != 0 && path[0] == 0; }

/* The guest program of the Burrow process named by @guest, a /proc/<pid>/...
 * path, read from its state like peer_ids() does; 0 if none (the launcher). */
static long remote_exe(const char* guest, char* out) {
    if (!starts_with(guest, "/proc/")) return 0;
    const char* p = guest + 6;
    long pid = (long) parse_unsigned(&p);
    if (p == guest + 6) return 0;
    struct {
        void* base;
        size_t length;
    } local = {out, PATH_MAX}, remote = {cfg.exe, PATH_MAX};
    if (sys6(NR_process_vm_readv, pid, (long) &local, 1, (long) &remote, 1, 0) != PATH_MAX) return 0;
    out[PATH_MAX - 1] = 0;
    return length_of(out);
}

static long do_readlink(long dirfd, const char* path, char* buf, long size) {
    if (size <= 0) return -EINVAL;
    if (empty(path)) return sys(NR_readlinkat, dirfd, path, buf, size);
    char guest[PATH_MAX], host[PATH_MAX], target[PATH_MAX];
    if (path == 0) return -EFAULT;
    long r = guest_absolute(dirfd, path, guest);
    if (r < 0) return r;
    if (same(guest, "/proc/self/exe") || same(guest, "/proc/thread-self/exe")) {
        r = copy(target, PATH_MAX, cfg.exe);
    } else {
        r = to_host(guest, 0, host, 0);
        if (r < 0) return r;
        r = sys(NR_readlinkat, AT_FDCWD, host, target, PATH_MAX - 1);
        if (r < 0) return r;
        target[r] = 0;
        /* Another process's exe is Burrow: KWin finds its clients' desktop files by it. */
        long n = same(target, cfg.self) ? remote_exe(guest, target) : 0;
        if (n > 0) r = n;
        else if (target[0] == '/') r = host_to_guest(target, target, PATH_MAX);
    }
    if (r < 0) return r;
    if (r > size) r = size;
    memcpy(buf, target, r);
    return r;
}

static long do_getcwd(char* buf, long size) {
    char host[PATH_MAX], guest[PATH_MAX];
    long r = sys(NR_getcwd, host, PATH_MAX, 0, 0);
    if (r < 0) return r;
    r = host_to_guest(host, guest, PATH_MAX);
    if (r < 0) return r;
    if (r + 1 > size) return -ERANGE;
    memcpy(buf, guest, r + 1);
    return r + 1;
}

/* fchownat(): a fake root's chown succeeds on any file it can see. */
static long do_chown(long dirfd, const char* path, long flags) {
    struct kstat st;
    if (empty(path) && (flags & AT_EMPTY_PATH)) return sys(NR_fstat, dirfd, &st, 0, 0);
    ON_HOST(!(flags & AT_SYMLINK_NOFOLLOW), sys(NR_newfstatat, AT_FDCWD, host, &st, AT_SYMLINK_NOFOLLOW));
}

/* stat() and lstat(): a faked hard link shows as its file. The last
 * component is looked at unfollowed first: most are no symlink, and that one
 * call answers both. */
static long do_stat(long dirfd, const char* path, struct kstat* st, long flags) {
    long r;
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        r = sys(NR_newfstatat, dirfd, path, st, flags);
    } else {
        char host[PATH_MAX];
        r = host_path(dirfd, path, 0, host);
        if (r == 0) r = sys(NR_newfstatat, AT_FDCWD, host, st, AT_SYMLINK_NOFOLLOW);
        if (r == -EACCES && proc_file(host) >= 0) r = proc_stat(st);
        if (r == 0 && (st->mode & S_IFMT) == S_IFLNK && !l2s_stat(host, st) && !(flags & AT_SYMLINK_NOFOLLOW)) {
            r = host_path(dirfd, path, 1, host);
            if (r == 0) r = sys(NR_newfstatat, AT_FDCWD, host, st, 0);
        }
    }
    fake_stat(r, st);
    return r;
}

static long do_statx(long dirfd, const char* path, long flags, long mask, struct kstatx* stx) {
    long r;
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        r = sys6(NR_statx, dirfd, (long) path, flags, mask, (long) stx, 0);
    } else {
        char host[PATH_MAX];
        long nofollow = (flags & ~AT_EMPTY_PATH) | AT_SYMLINK_NOFOLLOW;
        r = host_path(dirfd, path, 0, host);
        if (r == 0) r = sys6(NR_statx, AT_FDCWD, (long) host, nofollow, mask | 1 /* STATX_TYPE */, (long) stx, 0);
        if (r == -EACCES && proc_file(host) >= 0) r = proc_statx(stx);
        if (r == 0 && (stx->mode & S_IFMT) == S_IFLNK && !l2s_statx(host, nofollow, mask, stx) &&
            !(flags & AT_SYMLINK_NOFOLLOW)) {
            r = host_path(dirfd, path, 1, host);
            if (r == 0) r = sys6(NR_statx, AT_FDCWD, (long) host, nofollow & ~AT_SYMLINK_NOFOLLOW, mask, (long) stx, 0);
        }
    }
    fake_statx(r, stx);
    return r;
}

/* A Unix socket address with its path translated into @un; 0 if none to
 * translate. A host path too long for sockaddr_un goes through its directory,
 * opened as *@dir (closed by the caller after the syscall, -1 if none):
 * /proc/self/fd/<dir>/<name>. */
static long socket_address(const char* addr, long length, int follow, void* un, long* un_length, long* dir) {
    struct sockaddr {
        uint16_t family;
        char path[108];
    }* out = un;
    *dir = -1;
    if (addr == 0 || length <= 2 || *(const uint16_t*) addr != AF_UNIX || addr[2] == 0 /* abstract */) return 0;
    char path[109], host[PATH_MAX];
    long n = length - 2 < 108 ? length - 2 : 108;
    memcpy(path, addr + 2, n);
    path[n] = 0;
    long r = host_path(AT_FDCWD, path, follow, host);
    if (r < 0) return r;
    long h = length_of(host);
    if (h >= 108) {
        long slash = h;
        while (slash > 0 && host[slash] != '/') slash--;
        host[slash] = 0;
        long d = sys(NR_openat, AT_FDCWD, slash ? host : "/", O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
        if (d < 0) return d;
        char* end = format_unsigned((char*) memcpy(out->path, "/proc/self/fd/", 14) + 14, (unsigned long) d);
        if (end - out->path + (h - slash) >= 108) {
            sys(NR_close, d, 0, 0, 0);
            return -ENAMETOOLONG;
        }
        memcpy(end, host + slash, h - slash);
        end[0] = '/';
        end[h - slash] = 0;
        *dir = d;
        h = end + (h - slash) - out->path;
    } else {
        memcpy(out->path, host, h + 1);
    }
    out->family = AF_UNIX;
    *un_length = 2 + h + 1;
    return 1;
}

/* The guest's nameserver, 127.0.0.53:53, becomes the app's DNS proxy
 * (DnsProxy.kt) in @out: Android's resolver answers. */
static int dns_address(const char* addr, long length, char* out) {
    static const char nameserver[6] = {0, 53, 127, 0, 0, 53}; /* port and address, big-endian */
    if (cfg.dns_port == 0 || addr == 0 || length < 8 || *(const uint16_t*) addr != AF_INET ||
        memcmp(addr + 2, nameserver, 6) != 0)
        return 0;
    memset(out, 0, 16);
    memcpy(out, addr, 2);
    out[2] = (char) (cfg.dns_port >> 8);
    out[3] = (char) cfg.dns_port;
    out[4] = 127, out[7] = 1;
    return 1;
}

/* bind() on a Unix socket path, connect() on one or to the nameserver. */
static long do_socket_path(long nr, long fd, const char* addr, long length) {
    char un[110];
    long un_length, dir;
    if (nr == NR_connect && dns_address(addr, length, un)) return sys(nr, fd, un, 16, 0);
    long r = socket_address(addr, length, nr == NR_connect, un, &un_length, &dir);
    if (r < 0) return r;
    if (r == 0) return sys(nr, fd, addr, length, 0);
    r = sys(nr, fd, un, un_length, 0);
    if (dir >= 0) sys(NR_close, dir, 0, 0, 0);
    return r;
}

struct kmsghdr {
    void* name;
    uint32_t namelen;
    void* iov;
    size_t iovlen;
    void* control;
    size_t controllen;
    int flags;
};

/* sendmsg(): SCM_CREDENTIALS must carry the real ids (D-Bus and X11 clients
 * send their own, which are fake), and a datagram's destination path the
 * host's. */
static long do_sendmsg(long fd, const struct kmsghdr* m, long flags) {
    struct kmsghdr copy;
    char control[1024], un[110];
    int changed = 0;
    long dir = -1;
    if (m != 0 && m->control != 0 && m->controllen >= 16 && m->controllen <= sizeof(control)) {
        for (size_t at = 0; at + 16 <= m->controllen;) {
            const char* c = (const char*) m->control + at;
            size_t length = *(const size_t*) c;
            if (length < 16 || at + length > m->controllen) break;
            if (*(const int*) (c + 8) == 1 /* SOL_SOCKET */ && *(const int*) (c + 12) == 2 /* SCM_CREDENTIALS */ &&
                length >= 16 + 12) {
                if (!changed) {
                    memcpy(control, m->control, m->controllen);
                    copy = *m;
                    copy.control = control;
                    changed = 1;
                }
                uint32_t* cred = (uint32_t*) (control + at + 16); /* pid, uid, gid */
                cred[1] = cfg.real_uid;
                cred[2] = cfg.real_gid;
            }
            at += (length + 7) & ~(size_t) 7;
        }
    }
    if (m != 0 && m->name != 0 && dns_address(m->name, m->namelen, un)) {
        if (!changed) copy = *m, changed = 1;
        copy.name = un;
        copy.namelen = 16;
    } else if (m != 0 && m->name != 0) {
        long un_length;
        long r = socket_address(m->name, m->namelen, 1, un, &un_length, &dir);
        if (r < 0) return r;
        if (r > 0) {
            if (!changed) copy = *m, changed = 1;
            copy.name = un;
            copy.namelen = (uint32_t) un_length;
        }
    }
    long r = sys(NR_sendmsg, fd, changed ? &copy : m, flags, 0);
    if (dir >= 0) sys(NR_close, dir, 0, 0, 0);
    return r;
}

static long do_sendto(const uint64_t* x) {
    char un[110];
    long un_length, dir;
    if (dns_address((const char*) x[4], (long) x[5], un))
        return sys6(NR_sendto, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) un, 16);
    long r = socket_address((const char*) x[4], (long) x[5], 1, un, &un_length, &dir);
    if (r < 0) return r;
    if (r == 0) return sys6(NR_sendto, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) x[4], (long) x[5]);
    r = sys6(NR_sendto, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) un, un_length);
    if (dir >= 0) sys(NR_close, dir, 0, 0, 0);
    return r;
}

/* recvfrom(): answers of the DNS proxy come from the nameserver, else
 * resolvers (glibc's, c-ares) drop them. */
static long do_recvfrom(const uint64_t* x) {
    long r = sys6(NR_recvfrom, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) x[4], (long) x[5]);
    char* from = (char*) x[4];
    if (r < 0 || cfg.dns_port == 0 || from == 0 || x[5] == 0 || *(const uint32_t*) x[5] < 8 ||
        *(const uint16_t*) from != AF_INET)
        return r;
    static const char proxy_address[4] = {127, 0, 0, 1};
    if ((((unsigned char) from[2] << 8) | (unsigned char) from[3]) == cfg.dns_port &&
        memcmp(from + 4, proxy_address, 4) == 0) {
        from[2] = 0, from[3] = 53;
        from[7] = 53;
    }
    return r;
}

/* getsockname(), getpeername(): a Unix socket's host path becomes the guest's. */
static long do_sockname(long nr, long fd, char* addr, uint32_t* length) {
    char a[129];
    uint32_t n = sizeof(a) - 1;
    long r = sys(nr, fd, a, &n, 0);
    if (r < 0) return r;
    if (n > 2 && n < sizeof(a) && *(const uint16_t*) a == AF_UNIX && a[2] == '/') {
        char guest[PATH_MAX];
        a[n] = 0;
        long g = host_to_guest(a + 2, guest, sizeof(guest));
        if (g >= 0 && g < 108) {
            memcpy(a + 2, guest, g + 1);
            n = (uint32_t) (2 + g + 1);
        }
    }
    if (length == 0) return -EFAULT;
    memcpy(addr, a, *length < n ? *length : n);
    *length = n;
    return 0;
}

/* The emulated ids of Burrow process @pid, read where Burrow keeps them:
 * its image is at the same address in every process. */
static int peer_ids(long pid, uint32_t* ids) {
    char link[48] = "/proc/", exe[512];
    char* end = format_unsigned(link + 6, (unsigned long) pid);
    memcpy(end, "/exe", 5);
    long n = sys(NR_readlinkat, AT_FDCWD, link, exe, sizeof(exe) - 1);
    if (n <= 0) return 0;
    exe[n] = 0;
    if (!same(exe, cfg.self)) return 0;
    struct {
        void* base;
        size_t length;
    } local = {ids, sizeof(cfg.ids)}, remote = {cfg.ids, sizeof(cfg.ids)};
    return sys6(NR_process_vm_readv, pid, (long) &local, 1, (long) &remote, 1, 0) == (long) sizeof(cfg.ids);
}

/* getsockopt(SO_PEERCRED): the peer's real ids become its fake ones, root's
 * when they cannot be read. */
static long do_peercred(const uint64_t* x) {
    long r = sys6(NR_getsockopt, (long) x[0], (long) x[1], (long) x[2], (long) x[3], (long) x[4], 0);
    if (r < 0 || x[1] != 1 /* SOL_SOCKET */ || x[4] == 0 || *(const uint32_t*) x[4] < 12) return r;
    uint32_t* cred = (uint32_t*) x[3]; /* pid, uid, gid */
    uint32_t ids[ID_COUNT];
    int known = peer_ids(cred[0], ids);
    if (cred[1] == cfg.real_uid) cred[1] = known ? ids[EUID] : 0;
    if (cred[2] == cfg.real_gid) cred[2] = known ? ids[EGID] : 0;
    return r;
}

/* DRM_IOCTL_VERSION: the guest's render node is KGSL, which knows no DRM
 * ioctl, and Chromium's GPU process dies without a version. KGSL answers as
 * "kgsl": Mesa's loader is told its driver (zink), Turnip's msm probe skips
 * any name but "msm". */
static long do_drm_version(const uint64_t* x) {
    long r = sys(NR_ioctl, x[0], x[1], x[2], 0);
    if (r != -25 /* ENOTTY */ && r != -EINVAL) return r;
    char link[32] = "/proc/self/fd/", target[32];
    format_unsigned(link + 14, (unsigned long) (int) x[0]);
    long n = sys(NR_readlinkat, AT_FDCWD, link, target, sizeof(target) - 1);
    if (n < 0) return r;
    target[n] = 0;
    if (!same(target, "/dev/kgsl-3d0")) return r;
    struct drm_version {
        int major, minor, patchlevel;
        size_t name_length;
        char* name;
        size_t date_length;
        char* date;
        size_t desc_length;
        char* desc;
    }* v = (struct drm_version*) x[2];
    if (v == 0) return -EFAULT;
    static const char* const strings[] = {"kgsl", "20260101", "Qualcomm KGSL (DroidNux)"};
    size_t* lengths[] = {&v->name_length, &v->date_length, &v->desc_length};
    char* buffers[] = {v->name, v->date, v->desc};
    v->major = 1, v->minor = 0, v->patchlevel = 0;
    for (int i = 0; i < 3; i++) {
        size_t length = (size_t) length_of(strings[i]);
        if (buffers[i] != 0) memcpy(buffers[i], strings[i], *lengths[i] < length ? *lengths[i] : length);
        *lengths[i] = length;
    }
    return 0;
}

/* -- execve ------------------------------------------------------------------------------ */

static void* map(long size) {
    long p = sys6(NR_mmap, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p < 0 && p > -4096 ? 0 : (void*) p;
}

/* Reads "#!interpreter [argument]" from @head (@n bytes). Returns 1 with the
 * strings cut in place, 0 if it is no script. */
static int shebang(char* head, long n, char** interpreter, char** argument) {
    if (n < 2 || head[0] != '#' || head[1] != '!') return 0;
    long i = 2, end = 2;
    while (end < n && head[end] != '\n') end++;
    head[end < n ? end : n - 1] = 0;
    while (head[i] == ' ' || head[i] == '\t') i++;
    *interpreter = head + i;
    while (head[i] && head[i] != ' ' && head[i] != '\t') i++;
    *argument = 0;
    if (head[i]) {
        head[i++] = 0;
        while (head[i] == ' ' || head[i] == '\t') i++;
        if (head[i]) {
            *argument = head + i;
            long last = length_of(head + i) - 1;
            while (last >= 0 && (head[i + last] == ' ' || head[i + last] == '\t')) head[i + last--] = 0;
        }
    }
    return **interpreter != 0;
}

long emulate_execve(long dirfd, const char* path, char* const* argv, char* const* envp, long flags) {
    char guest[PATH_MAX], host[PATH_MAX], resolved[PATH_MAX];
    char heads[4][256];
    /* argv's head after the scripts' interpreters: at each level the kernel
     * runs "interpreter [argument] file args[1..]". */
    const char* head[12];
    int head_count = 1;
    const char* file = path;
    long r;
    if (path == 0) return -EFAULT;
    head[0] = argv != 0 ? argv[0] : 0;
    if (empty(path) && (flags & AT_EMPTY_PATH)) {
        char link[32] = "/proc/self/fd/";
        format_unsigned(link + 14, (unsigned long) (int) dirfd);
        r = sys(NR_readlinkat, AT_FDCWD, link, host, PATH_MAX - 1);
        if (r < 0) return -EBADF;
        host[r] = 0;
        r = host_to_guest(host, guest, PATH_MAX);
    } else {
        if (path[0] == 0) return -ENOENT;
        r = guest_absolute(dirfd, path, guest);
    }
    if (r < 0) return r;
    /* The process name: the base name of the file execve() was given. */
    char name[16];
    const char* b = guest;
    for (const char* p = guest; *p; p++)
        if (*p == '/' && p[1]) b = p + 1;
    long l = 0;
    while (b[l] && b[l] != '/' && l < 15) name[l] = b[l], l++;
    name[l] = 0;
    uint32_t set_ids_mode = 0; /* S_ISUID and S_ISGID of the file itself (scripts' are ignored, as by Linux) */
    for (int depth = 0;; depth++) {
        r = to_host(guest, !(flags & AT_SYMLINK_NOFOLLOW), host, resolved);
        if (r < 0) return r;
        struct kstat st;
        r = sys(NR_newfstatat, AT_FDCWD, host, &st, 0);
        if (r < 0) return r;
        if ((st.mode & S_IFMT) != S_IFREG) return -EACCES;
        if (depth == 0) set_ids_mode = st.mode & (S_ISUID | S_ISGID);
        r = sys(NR_faccessat, AT_FDCWD, host, X_OK, 0);
        if (r < 0) return r;
        long fd = sys(NR_openat, AT_FDCWD, host, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) return fd;
        char* h = heads[depth];
        long n = sys(NR_pread64, fd, h, sizeof(heads[0]) - 1, 0);
        sys(NR_close, fd, 0, 0, 0);
        if (n < 0) return n;
        h[n] = 0;
        if (n >= 20 && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
            if (h[4] != 2 /* ELFCLASS64 */ || *(uint16_t*) (h + 18) != 183 /* EM_AARCH64 */) return -ENOEXEC;
            break;
        }
        char *interpreter, *argument;
        if (!shebang(h, n, &interpreter, &argument)) return -ENOEXEC;
        if (depth == 3) return -ELOOP;
        const char* rest[12];
        int rest_count = head_count - 1;
        memcpy(rest, head + 1, rest_count * sizeof(*rest));
        head_count = 0;
        head[head_count++] = interpreter;
        if (argument) head[head_count++] = argument;
        head[head_count++] = file;
        memcpy(head + head_count, rest, rest_count * sizeof(*rest));
        head_count += rest_count;
        file = interpreter;
        flags &= ~AT_SYMLINK_NOFOLLOW;
        r = guest_absolute(AT_FDCWD, interpreter, guest);
        if (r < 0) return r;
        set_ids_mode = 0;
    }

    long argc = 0, envc = 0;
    while (argv != 0 && argv[argc] != 0) argc++;
    while (envp != 0 && envp[envc] != 0) envc++;

    long words = head_count + argc + envc + 3;
    long state_size = 3 * PATH_MAX + MAX_BINDS * 800;
    long size = words * 8 + state_size;
    char** block = map(size);
    if (block == 0) return -ENOMEM;
    char* state = (char*) (block + words);
    memcpy(state, "BURROW=", 7);
    /* Set-user-ID and set-group-ID programs (sudo, su): every file is the
     * app's, shown as root's to root, so they take root's ids. The old ids
     * come back if the execve() fails. */
    uint32_t old_ids[ID_COUNT];
    for (int i = 0; i < ID_COUNT; i++) old_ids[i] = id(i);
    if (set_ids_mode & S_ISUID) set_id(EUID, 0), set_id(SUID, 0), set_id(FSUID, 0);
    if (set_ids_mode & S_ISGID) set_id(EGID, 0), set_id(SGID, 0), set_id(FSGID, 0);
    r = encode_config(state + 7, state_size - 7, resolved, host, name);
    for (int i = 0; i < ID_COUNT; i++) set_id(i, old_ids[i]);
    if (r < 0) {
        sys(NR_munmap, block, size, 0, 0);
        return r;
    }
    char** new_argv = block;
    long a = 0;
    for (int i = 0; i < head_count; i++)
        if (head[i] != 0) new_argv[a++] = (char*) head[i];
    for (long i = 1; i < argc; i++) new_argv[a++] = argv[i];
    new_argv[a++] = 0;
    char** new_envp = new_argv + a;
    long e = 0;
    for (long i = 0; i < envc; i++)
        if (!starts_with(envp[i], "BURROW=")) new_envp[e++] = envp[i];
    new_envp[e++] = state;
    new_envp[e] = 0;
    r = sys(NR_execve, cfg.self, new_argv, new_envp, 0);
    sys(NR_munmap, block, size, 0, 0);
    return r;
}

/* openat()/openat2() of @host; @a and @b are the call's third and fourth
 * arguments. Root opens files whatever their mode: when the fake root is
 * refused a file of the app's, it gets the permission it lacks for the time
 * of the open, as proot lends u+rw. */
static long open_as_root(long nr, const char* host, long flags, long a, long b) {
    if (!(flags & O_PATH) && proc_maps(host)) return proc_maps_open(host, flags);
    long r = sys(nr, AT_FDCWD, host, a, b);
    int proc = r == -EACCES && !(flags & O_PATH) ? proc_file(host) : -1;
    if (proc >= 0) return proc_open(proc, flags);
    if (r != -EACCES || id(FSUID) != 0 || (flags & O_PATH)) return r;
    struct kstat st;
    if (sys(NR_newfstatat, AT_FDCWD, host, &st, 0) < 0 || st.uid != cfg.real_uid) return r;
    uint32_t need = (flags & 3) == 0 ? 0400 : (flags & 3) == 1 ? 0200 : 0600;
    if ((st.mode & need) == need) return r;
    if (sys(NR_fchmodat, AT_FDCWD, host, (st.mode & 07777) | need, 0) < 0) return r;
    r = sys(nr, AT_FDCWD, host, a, b);
    sys(NR_fchmodat, AT_FDCWD, host, st.mode & 07777, 0);
    return r;
}

/* faccessat() of @host: the made-up files of /proc are readable. */
static long access_host(long nr, const char* host, long mode, long flags) {
    long r = sys(nr, AT_FDCWD, host, mode, flags);
    if (r == -EACCES && !(mode & 3 /* W_OK | X_OK */) && proc_file(host) >= 0) return 0;
    return r;
}

/* chroot(): the directory becomes the rootfs, the bindings below it stay.
 * shortcut: SysV shm and link2symlink's links of the old root are not seen
 * from the new one; keep the first root if a chrooted program needs them. */
static long do_chroot(const char* path) {
    char host[PATH_MAX], absolute[PATH_MAX], guest[PATH_MAX], root[sizeof(cfg.root)];
    if (id(EUID) != 0) return -EPERM;
    if (path == 0) return -EFAULT;
    if (path[0] == 0) return -ENOENT;
    long r = guest_absolute(AT_FDCWD, path, absolute);
    if (r >= 0) r = to_host(absolute, 1, host, guest);
    if (r < 0) return r;
    long fd = sys(NR_openat, AT_FDCWD, host, O_PATH | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return fd;
    char link[32] = "/proc/self/fd/";
    format_unsigned(link + 14, (unsigned long) fd);
    long n = sys(NR_readlinkat, AT_FDCWD, link, root, sizeof(root) - 1);
    sys(NR_close, fd, 0, 0, 0);
    if (n <= 0) return n < 0 ? n : -ENOENT;
    if (n == (long) sizeof(root) - 1) return -ENAMETOOLONG;
    root[n] = 0;
    long g = length_of(guest);
    if (g == 1) return 0; /* "/" */
    /* shortcut: other threads may resolve a path meanwhile; chroot() comes before them in practice. */
    int kept = 0;
    for (int i = 0; i < cfg.bind_count; i++) {
        struct bind* b = &cfg.binds[i];
        if (b->guest_length <= g || memcmp(b->guest, guest, g) != 0 || b->guest[g] != '/') continue;
        struct bind* k = &cfg.binds[kept++];
        memmove(k->host, b->host, b->host_length + 1);
        k->host_length = b->host_length;
        k->guest_length = b->guest_length - g;
        memmove(k->guest, b->guest + g, k->guest_length + 1);
    }
    cfg.bind_count = kept;
    memcpy(cfg.root, root, n + 1);
    cfg.root_length = n;
    set_root_alias();
    return 0;
}

/* -- Dispatch ------------------------------------------------------------------------------- */

static long emulate(long nr, const uint64_t* x) {
    long dirfd = (long) (int) x[0];
    const char* path = (const char*) x[1];
    switch (nr) {
    case NR_openat: {
        long flags = (long) x[2];
        /* An O_TMPFILE file gets its name from linkat(), which Android
         * refuses: say it is unsupported, so programs (Qt's QTemporaryFile,
         * glibc's tmpfile()) fall back to a named file. */
        if (flags & 020000000 /* __O_TMPFILE */) return -95 /* EOPNOTSUPP */;
        int follow = !(flags & O_NOFOLLOW) && (flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL);
        ON_HOST(follow, open_as_root(NR_openat, host, flags, flags, (long) x[3]));
    }
    case NR_openat2: {
        const struct open_how* how = (const struct open_how*) x[2];
        int follow = !(how->flags & O_NOFOLLOW) && (how->flags & (O_CREAT | O_EXCL)) != (O_CREAT | O_EXCL);
        ON_HOST(follow, open_as_root(NR_openat2, host, (long) how->flags, (long) how, (long) x[3]));
    }
    case NR_newfstatat: return do_stat(dirfd, path, (struct kstat*) x[2], (long) x[3]);
    case NR_fstat: {
        long r = sys(NR_fstat, x[0], x[1], 0, 0);
        fake_stat(r, (struct kstat*) x[1]);
        return r;
    }
    case NR_statx: return do_statx(dirfd, path, (long) x[2], (long) x[3], (struct kstatx*) x[4]);
    case NR_faccessat: ON_HOST(1, access_host(NR_faccessat, host, (long) x[2], 0));
    case NR_faccessat2:
        if (empty(path) && (x[3] & AT_EMPTY_PATH)) return sys(NR_faccessat2, x[0], path, x[2], x[3]);
        ON_HOST(!(x[3] & AT_SYMLINK_NOFOLLOW), access_host(NR_faccessat2, host, (long) x[2], (long) x[3]));
    case NR_readlinkat: return do_readlink(dirfd, path, (char*) x[2], (long) x[3]);
    case NR_getcwd: return do_getcwd((char*) x[0], (long) x[1]);
    case NR_chdir: {
        dirfd = AT_FDCWD;
        path = (const char*) x[0];
        ON_HOST(1, sys(NR_chdir, host, 0, 0, 0));
    }
    case NR_chroot: return do_chroot((const char*) x[0]);
    case NR_mkdirat: ON_HOST(0, sys(NR_mkdirat, AT_FDCWD, host, x[2], 0));
    case NR_mknodat: ON_HOST(0, sys(NR_mknodat, AT_FDCWD, host, x[2], x[3]));
    case NR_unlinkat: {
        char host[PATH_MAX];
        long r = host_path(dirfd, path, 0, host);
        if (r < 0) return r;
        if (!(x[2] & 0x200 /* AT_REMOVEDIR */) && (r = l2s_unlinked(host)) < 0) return r;
        r = sys(NR_unlinkat, AT_FDCWD, host, x[2], 0);
        if (r != -EACCES || id(FSUID) != 0) return r;
        /* Root removes from read-only directories too (rm -rf of Go's module cache). */
        long slash = length_of(host);
        while (slash > 0 && host[slash] != '/') slash--;
        if (slash == 0) return r;
        host[slash] = 0;
        struct kstat st;
        if (sys(NR_newfstatat, AT_FDCWD, host, &st, 0) < 0 || st.uid != cfg.real_uid || (st.mode & 0300) == 0300 ||
            sys(NR_fchmodat, AT_FDCWD, host, (st.mode & 07777) | 0300, 0) < 0)
            return r;
        host[slash] = '/';
        r = sys(NR_unlinkat, AT_FDCWD, host, x[2], 0);
        host[slash] = 0;
        sys(NR_fchmodat, AT_FDCWD, host, st.mode & 07777, 0);
        return r;
    }
    case NR_symlinkat: {
        dirfd = (long) (int) x[1];
        path = (const char*) x[2];
        ON_HOST(0, sys(NR_symlinkat, x[0], AT_FDCWD, host, 0));
    }
    case NR_linkat: {
        char from[PATH_MAX], to[PATH_MAX];
        long flags = (long) x[4];
        long r;
        if (empty(path) && (flags & AT_EMPTY_PATH)) {
            /* The file of descriptor @dirfd, by its host path: an unnamed one (O_TMPFILE) cannot get a name. */
            char link[32] = "/proc/self/fd/";
            format_unsigned(link + 14, (unsigned long) dirfd);
            r = sys(NR_readlinkat, AT_FDCWD, link, from, PATH_MAX - 1);
            if (r < 0) return r == -ENOENT ? -EBADF : r;
            from[r] = 0;
            if (from[0] != '/' || (r > 10 && same(from + r - 10, " (deleted)"))) return -ENOENT;
            flags = 0;
        } else {
            r = host_path(dirfd, path, (flags & AT_SYMLINK_FOLLOW) != 0, from);
        }
        if (r < 0) return r;
        r = host_path((long) (int) x[2], (const char*) x[3], 0, to);
        if (r < 0) return r;
        r = sys6(NR_linkat, AT_FDCWD, (long) from, AT_FDCWD, (long) to, flags & AT_SYMLINK_FOLLOW, 0);
        return r == -EACCES || r == -EPERM ? l2s_link(from, to) : r;
    }
    case NR_renameat:
    case NR_renameat2: {
        char from[PATH_MAX];
        long r = host_path(dirfd, path, 0, from);
        if (r < 0) return r;
        char to[PATH_MAX];
        r = host_path((long) (int) x[2], (const char*) x[3], 0, to);
        if (r < 0) return r;
        /* A faked hard link replaced: one link less. */
        if ((r = l2s_unlinked(to)) < 0) return r;
        return sys6(NR_renameat2, AT_FDCWD, (long) from, AT_FDCWD, (long) to, nr == NR_renameat ? 0 : (long) x[4], 0);
    }
    case NR_fchmodat: ON_HOST(1, sys(NR_fchmodat, AT_FDCWD, host, x[2], 0));
    case NR_fchmodat2:
        if (empty(path) && (x[3] & AT_EMPTY_PATH)) return sys(NR_fchmodat2, x[0], path, x[2], x[3]);
        ON_HOST(!(x[3] & AT_SYMLINK_NOFOLLOW), sys(NR_fchmodat2, AT_FDCWD, host, x[2], x[3] & ~AT_EMPTY_PATH));
    case NR_fchownat: return do_chown(dirfd, path, (long) x[4]);
    case NR_fchown: {
        struct kstat st;
        return sys(NR_fstat, x[0], &st, 0, 0);
    }
    case NR_utimensat:
        if (path == 0) return sys(NR_utimensat, x[0], 0, x[2], x[3]);
        if (empty(path) && (x[3] & AT_EMPTY_PATH)) return sys(NR_utimensat, x[0], path, x[2], x[3]);
        ON_HOST(!(x[3] & AT_SYMLINK_NOFOLLOW), sys(NR_utimensat, AT_FDCWD, host, x[2], x[3]));
    case NR_truncate:
    case NR_statfs:
    case NR_setxattr:
    case NR_lsetxattr:
    case NR_getxattr:
    case NR_lgetxattr:
    case NR_listxattr:
    case NR_llistxattr:
    case NR_removexattr:
    case NR_lremovexattr: {
        int follow = nr != NR_lsetxattr && nr != NR_lgetxattr && nr != NR_llistxattr && nr != NR_lremovexattr;
        dirfd = AT_FDCWD;
        path = (const char*) x[0];
        ON_HOST(follow, sys6(nr, (long) host, (long) x[1], (long) x[2], (long) x[3], (long) x[4], 0));
    }
    case NR_inotify_add_watch:
        dirfd = AT_FDCWD;
        ON_HOST(!(x[2] & IN_DONT_FOLLOW), sys(NR_inotify_add_watch, x[0], host, x[2], 0));
    case NR_bind:
    case NR_connect: return do_socket_path(nr, (long) x[0], (const char*) x[1], (long) x[2]);
    case NR_sendmsg: return do_sendmsg((long) x[0], (const struct kmsghdr*) x[1], (long) x[2]);
    case NR_sendto: return do_sendto(x);
    case NR_recvfrom: return do_recvfrom(x);
    case NR_getsockname:
    case NR_getpeername: return do_sockname(nr, (long) x[0], (char*) x[1], (uint32_t*) x[2]);
    case NR_getsockopt: return do_peercred(x);
    case NR_ioctl: return do_drm_version(x);
    case NR_shmget:
    case NR_shmctl:
    case NR_shmat:
    case NR_shmdt: return emulate_sysv(nr, x);
    case NR_execve:
        return emulate_execve(AT_FDCWD, (const char*) x[0], (char* const*) x[1], (char* const*) x[2], 0);
    case NR_execveat:
        return emulate_execve(dirfd, path, (char* const*) x[2], (char* const*) x[3], (long) x[4]);

    case NR_getuid: return id(RUID);
    case NR_geteuid: return id(EUID);
    case NR_getgid: return id(RGID);
    case NR_getegid: return id(EGID);
    case NR_getresuid: return get_ids(RUID, (uint32_t*) x[0], (uint32_t*) x[1], (uint32_t*) x[2]);
    case NR_getresgid: return get_ids(RGID, (uint32_t*) x[0], (uint32_t*) x[1], (uint32_t*) x[2]);
    case NR_setuid: return set_ids(RUID, (uint32_t) x[0], 0, 0, 1);
    case NR_setgid: return set_ids(RGID, (uint32_t) x[0], 0, 0, 1);
    case NR_setreuid: return set_ids(RUID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) -1, 2);
    case NR_setregid: return set_ids(RGID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) -1, 2);
    case NR_setresuid: return set_ids(RUID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) x[2], 3);
    case NR_setresgid: return set_ids(RGID, (uint32_t) x[0], (uint32_t) x[1], (uint32_t) x[2], 3);
    case NR_setfsuid: return set_fs_id(RUID, (uint32_t) x[0]);
    case NR_setfsgid: return set_fs_id(RGID, (uint32_t) x[0]);
    case NR_getgroups: {
        long size = (long) (int) x[0];
        if (size == 0) return cfg.group_count;
        if (size < cfg.group_count) return -EINVAL;
        if (x[1] == 0) return -EFAULT;
        memcpy((uint32_t*) x[1], cfg.groups, cfg.group_count * sizeof(uint32_t));
        return cfg.group_count;
    }
    case NR_setgroups: {
        long size = (long) x[0];
        if (id(EUID) != 0) return -EPERM;
        /* shortcut: more groups than MAX_GROUPS fail; raise it if a program needs them. */
        if (size < 0 || size > MAX_GROUPS) return -EINVAL;
        if (size > 0 && x[1] == 0) return -EFAULT;
        memcpy(cfg.groups, (const uint32_t*) x[1], size * sizeof(uint32_t));
        cfg.group_count = (int) size;
        return 0;
    }

    case NR_lseek:
        proc_rewind((long) x[0]);
        return sys(NR_lseek, x[0], x[1], x[2], 0);

    case NR_rt_sigaction:
        return do_sigaction((long) x[0], (const struct ksigaction*) x[1], (struct ksigaction*) x[2], (long) x[3]);
    }
    return -ENOSYS;
}

static __attribute__((noinline)) void on_sigsys(int sig, struct ksiginfo* info, struct kucontext* uc) {
    if (info->code != SYS_SECCOMP || info->errno_ != TRAP_DATA) {
        foreign(sig, info, uc);
        return;
    }
    uint64_t* x = uc->mcontext.regs;
    if (info->syscall == NR_rt_sigprocmask) {
        x[0] = (uint64_t) do_sigprocmask(&uc->sigmask, (long) x[0], (const uint64_t*) x[1], (uint64_t*) x[2],
                                         (long) x[3]);
        return;
    }
    x[0] = (uint64_t) emulate(info->syscall, x);
}

/* The handler needs tens of KB, more than the signal stacks guests set up
 * (Firefox's threads: 20 KB), so it runs on one of these, owned by a thread id.
 * The stack is also the thread's sigaltstack meanwhile: a nested signal (a
 * trapped syscall in a guest SIGSYS handler) must go below it, not at the top
 * of the guest's sigaltstack, where the outer frame lives. */
#define STACKS 32
#define STACK_SIZE (128 * 1024)
static char* stacks;
static int stack_owner[STACKS];

extern void burrow_call_on_stack(long a, void* b, void* c, void* fn, char* top);

static int claim_stack(void) {
    int tid = (int) sys(NR_gettid, 0, 0, 0, 0);
    for (int pass = 0; stacks != 0 && pass < 2; pass++) {
        for (int i = 0; i < STACKS; i++) {
            int free_slot = 0;
            if (__atomic_compare_exchange_n(&stack_owner[i], &free_slot, tid, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
                return i;
        }
        /* Owners gone: the parent's threads after a fork, a vfork child that
         * exec'd. shortcut: a live CLONE_VM child of another process can lose
         * its stack here, only when all are taken. */
        long pid = sys(NR_getpid, 0, 0, 0, 0);
        for (int i = 0; i < STACKS; i++) {
            int owner = __atomic_load_n(&stack_owner[i], __ATOMIC_RELAXED);
            if (owner != 0 && sys(NR_tgkill, pid, owner, 0, 0) == -ESRCH)
                __atomic_compare_exchange_n(&stack_owner[i], &owner, 0, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED);
        }
    }
    return -1;
}

static void on_sigsys_entry(int sig, struct ksiginfo* info, struct kucontext* uc) {
    struct {
        void* sp;
        int flags;
        size_t size;
    } ours, old;
    int slot = claim_stack();
    if (slot >= 0) {
        ours.sp = stacks + (long) slot * STACK_SIZE;
        ours.flags = 0;
        ours.size = STACK_SIZE;
        /* EPERM when already on the guest's sigaltstack: stay there. */
        if (sys(NR_sigaltstack, &ours, &old, 0, 0) < 0) {
            __atomic_store_n(&stack_owner[slot], 0, __ATOMIC_RELEASE);
            slot = -1;
        }
    }
    if (slot < 0) {
        on_sigsys(sig, info, uc);
        return;
    }
    burrow_call_on_stack(sig, info, uc, (void*) on_sigsys, (char*) ours.sp + STACK_SIZE);
    old.flags &= ~1; /* SS_ONSTACK, reported only */
    sys(NR_sigaltstack, &old, 0, 0, 0);
    __atomic_store_n(&stack_owner[slot], 0, __ATOMIC_RELEASE);
}

void install_handler(void) {
    long p = sys6(NR_mmap, 0, (long) STACKS * STACK_SIZE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    stacks = p < 0 && p > -4096 ? 0 : (char*) p;
    /* Not SA_ONSTACK: the kernel's frame goes on the thread's stack, as the
     * guest's sigaltstack may be too small for it and the handler both.
     * shortcut: goroutine stacks are small too; Go programs would need
     * SA_ONSTACK with a sigaltstack of ours. */
    struct ksigaction act = {(uintptr_t) on_sigsys_entry, SA_SIGINFO | SA_NODEFER, 0, 0};
    if (sys(NR_rt_sigaction, SIGSYS, &act, 0, 8) < 0) die("cannot install the SIGSYS handler", 0);
}
