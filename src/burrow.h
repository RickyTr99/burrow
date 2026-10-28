/*
 * Burrow: runs the programs of a Linux rootfs on Android (and arm64 Linux),
 * without root and without ptrace.
 *
 * Burrow is one static binary (linked at a fixed address) with two roles:
 *
 * - Launcher: the app (the user Burrow runs as; on Android, an app's uid)
 *   starts it with the rootfs, the bindings and a guest command. It installs a seccomp filter that traps the syscalls Burrow
 *   emulates (paths, ids, exec) with SIGSYS, unless they come from Burrow's
 *   own syscall gadget, then executes the command.
 *
 * - Loader: every guest execve() is emulated as an execve() of Burrow itself,
 *   with Burrow's state in the BURROW environment variable. Burrow removes the
 *   variable, installs its SIGSYS handler (the filter survives exec, handlers
 *   do not), maps the guest program and its ELF interpreter, fixes the
 *   auxiliary vector and jumps to it. Burrow's image stays mapped: the handler
 *   lives there.
 *
 * The handler runs on the trapping thread, in the guest process: an emulated
 * syscall costs about a microsecond, against ~60 for a ptrace stop. Guest
 * paths are resolved in the rootfs component by component (symlinks are
 * guest paths), bindings map guest directories to host ones, and the result
 * is a host path for the real syscall. Ids follow proot's fake_id0: the guest
 * runs as root and files owned by the app's uid show as the saved set-uid's.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#if !defined(__aarch64__)
#error "Burrow is arm64 only"
#endif

#define PATH_MAX 4096
#define MAX_BINDS 16
#define MAX_GROUPS 32
/* SECCOMP_RET_DATA of Burrow's filter, seen as si_errno: tells our traps
 * from those of the guest's own filters and of Android's. */
#define TRAP_DATA 0x0b07

/* -- Kernel interface (arm64, asm-generic) ------------------------------------ */

enum {
    NR_setxattr = 5, NR_lsetxattr = 6, NR_getxattr = 8, NR_lgetxattr = 9, NR_listxattr = 11, NR_llistxattr = 12,
    NR_removexattr = 14, NR_lremovexattr = 15, NR_getcwd = 17, NR_fcntl = 25, NR_ioctl = 29, NR_inotify_add_watch = 27,
    NR_mknodat = 33, NR_mkdirat = 34, NR_unlinkat = 35, NR_symlinkat = 36, NR_linkat = 37, NR_renameat = 38,
    NR_statfs = 43, NR_truncate = 45, NR_faccessat = 48, NR_chdir = 49, NR_chroot = 51, NR_fchmodat = 53, NR_fchownat = 54,
    NR_fchown = 55, NR_openat = 56, NR_close = 57, NR_lseek = 62, NR_read = 63, NR_write = 64, NR_pread64 = 67,
    NR_readlinkat = 78, NR_newfstatat = 79, NR_fstat = 80, NR_utimensat = 88, NR_exit_group = 94,
    NR_tgkill = 131, NR_sigaltstack = 132, NR_rt_sigaction = 134, NR_rt_sigprocmask = 135, NR_setregid = 143, NR_setgid = 144,
    NR_setreuid = 145, NR_setuid = 146, NR_setresuid = 147, NR_getresuid = 148, NR_setresgid = 149,
    NR_getresgid = 150, NR_setfsuid = 151, NR_setfsgid = 152, NR_getgroups = 158, NR_setgroups = 159, NR_prctl = 167,
    NR_getpid = 172, NR_getuid = 174, NR_geteuid = 175, NR_getgid = 176, NR_getegid = 177, NR_gettid = 178,
    NR_socket = 198, NR_bind = 200, NR_connect = 203, NR_getsockname = 204, NR_getpeername = 205, NR_sendto = 206, NR_recvfrom = 207, NR_getsockopt = 209, NR_sendmsg = 211, NR_munmap = 215, NR_execve = 221, NR_mmap = 222, NR_mprotect = 226,
    NR_renameat2 = 276, NR_seccomp = 277, NR_execveat = 281, NR_statx = 291, NR_openat2 = 437,
    NR_clone3 = 435, NR_faccessat2 = 439, NR_fchmodat2 = 452, NR_process_vm_readv = 270,
    NR_shmget = 194, NR_shmctl = 195, NR_shmat = 196, NR_shmdt = 197, NR_msgget = 186, NR_msgctl = 187,
    NR_msgrcv = 188, NR_msgsnd = 189, NR_semget = 190, NR_semctl = 191, NR_semtimedop = 192, NR_semop = 193,
};

enum {
    EPERM = 1, ENOENT = 2, ESRCH = 3, EINTR = 4, EIO = 5, E2BIG = 7, ENOEXEC = 8, EBADF = 9, ENOMEM = 12, EACCES = 13,
    EFAULT = 14, ENOTDIR = 20, EISDIR = 21, EINVAL = 22, ERANGE = 34, ENAMETOOLONG = 36, ENOSYS = 38,
    ELOOP = 40,
};

#define AT_FDCWD (-100)
#define AT_SYMLINK_NOFOLLOW 0x100
#define AT_SYMLINK_FOLLOW 0x400
#define AT_EMPTY_PATH 0x1000
#define O_RDONLY 0
#define O_CREAT 0100
#define O_EXCL 0200
#define O_DIRECTORY 040000
#define O_NOFOLLOW 0100000
#define O_CLOEXEC 02000000
#define O_PATH 010000000
#define RESOLVE_NO_SYMLINKS 0x04
#define S_IFMT 0170000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_ISUID 04000
#define S_ISGID 02000
#define S_IFDIR 0040000
#define STATX_UID 0x8u
#define STATX_GID 0x10u
#define IN_DONT_FOLLOW 0x02000000
#define X_OK 1
#define AF_UNIX 1
#define AF_INET 2
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 0x02
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_NORESERVE 0x4000
#define SIGSYS 31
#define SYS_SECCOMP 1
#define SA_SIGINFO 0x4
#define SA_ONSTACK 0x08000000
#define SA_NODEFER 0x40000000
#define SIG_BLOCK 0
#define SIG_SETMASK 2
#define PR_SET_KEEPCAPS 8
#define PR_SET_NO_NEW_PRIVS 38

struct open_how {
    uint64_t flags, mode, resolve;
};

struct kstat {
    uint64_t dev, ino;
    uint32_t mode, nlink, uid, gid;
    uint64_t rdev, pad1;
    int64_t size;
    int32_t blksize, pad2;
    int64_t blocks, times[6];
    uint32_t unused[2];
};

/* struct statx up to the device. */
struct kstatx {
    uint32_t mask, blksize;
    uint64_t attributes;
    uint32_t nlink, uid, gid;
    uint16_t mode, pad;
    uint64_t ino, size, blocks, attributes_mask;
    int64_t times[8];
    uint32_t rdev_major, rdev_minor, dev_major, dev_minor;
};

struct ksigaction {
    uintptr_t handler;
    unsigned long flags;
    uintptr_t restorer;
    uint64_t mask;
};

struct ksiginfo {
    int signo, errno_, code, pad;
    uintptr_t call_addr; /* SIGSYS */
    int syscall;
    unsigned arch;
};

struct ksigcontext {
    uint64_t fault_address;
    uint64_t regs[31];
    uint64_t sp, pc, pstate;
    uint8_t reserved[4096] __attribute__((aligned(16)));
};

struct kucontext {
    unsigned long flags;
    struct kucontext* link;
    struct {
        void* sp;
        int flags;
        size_t size;
    } stack;
    uint64_t sigmask;
    uint8_t unused[1024 / 8 - 8];
    struct ksigcontext mcontext;
};

/* -- State ---------------------------------------------------------------------- */

struct bind {
    char guest[256];
    char host[512];
    long guest_length, host_length;
};

enum { RUID, EUID, SUID, FSUID, RGID, EGID, SGID, FSGID, ID_COUNT };

struct config {
    char root[512]; /* the rootfs, a host path without symlinks */
    long root_length;
    char root_alias[512]; /* the same directory under /data/data (or /data/user/0) */
    long root_alias_length;
    char self[512]; /* Burrow's binary */
    struct bind binds[MAX_BINDS];
    int bind_count;
    uint32_t real_uid, real_gid;
    uint32_t ids[ID_COUNT]; /* the guest's, emulated; atomic */
    uint32_t groups[MAX_GROUPS]; /* its supplementary groups, emulated */
    int group_count;
    char exe[PATH_MAX];      /* the guest program, as a guest path */
    char host_exe[PATH_MAX]; /* and as a host path */
    char name[16];           /* its process name: the file execve() was given */
    uint16_t dns_port;       /* the app's DNS proxy on 127.0.0.1, 0 if none */
    char stats[512];         /* the statistics file (-s), a host path; empty if none */
};

extern struct config cfg;

/* -- Functions -------------------------------------------------------------------- */

/* A syscall through Burrow's gadget, which the filter lets through. */
static inline long sys6(long n, long a, long b, long c, long d, long e, long f) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    register long x8 __asm__("x8") = n;
    __asm__ volatile("bl burrow_gadget"
                     : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
                     : "x30", "memory", "cc");
    return x0;
}
#define sys(n, a, b, c, d) sys6(n, (long) (a), (long) (b), (long) (c), (long) (d), 0, 0)

/* util.c */
void* memcpy(void* to, const void* from, size_t n);
void* memmove(void* to, const void* from, size_t n);
void* memset(void* to, int c, size_t n);
int memcmp(const void* a, const void* b, size_t n);
long length_of(const char* s);
int same(const char* a, const char* b);
int starts_with(const char* s, const char* prefix);
long copy(char* to, long size, const char* from); /* -ENAMETOOLONG if it does not fit */
char* format_unsigned(char* to, unsigned long value);
unsigned long parse_unsigned(const char** s);
void say(const char* a, const char* b, const char* c);
__attribute__((noreturn)) void die(const char* a, const char* b);

/* config.c */
void set_root_alias(void);
/* The state for a new program @exe (guest path), @host_exe, named @name. */
long encode_config(char* to, long size, const char* exe, const char* host_exe, const char* name);
int decode_config(const char* s);

/* path.c */
long guest_absolute(long dirfd, const char* path, char* out);
long to_host(const char* guest, int follow, char* host, char* resolved);
long host_path(long dirfd, const char* path, int follow, char* host);
long host_to_guest(const char* host, char* out, long size);
/* host_path() for a call that creates nothing, in one walk when it can: *@fd
 * is then the file, opened O_PATH (to be closed), else -1 and @host is to be
 * used. ENOENT is final: no directory is checked for a file to create. */
long host_fd(long dirfd, const char* path, int follow, char* host, long* fd);
/* openat() in one walk, when the kernel resolves the path as we would: a
 * plain path and no symlink. -ELOOP, -EINVAL (openat2() is stricter) and
 * -EACCES (the fake root's permissions) mean taking to_host()'s way. */
long open_direct(long dirfd, const char* path, long flags, long mode);

/* trap.c */
void install_handler(void);
long install_filter(void);
long emulate_execve(long dirfd, const char* path, char* const* argv, char* const* envp, long flags);

/* Statistics (-s): Burrow's own steps, counted past the syscalls. */
enum { STATS_PROBE = 500, STATS_WALK = 501, STATS_OPEN = 502 };
uint64_t stats_start(void);
void stats_step(int step, uint64_t start);

/* sysv.c */
long emulate_sysv(long nr, const uint64_t* x);

/* procfs.c: the files of /proc that Android refuses, made up. */
int proc_file(const char* host); /* its index, -1 if none */
long proc_open(int which, long flags);
void proc_rewind(long fd); /* lseek(fd, 0, SEEK_SET): a made-up file's content made again */
int proc_maps(const char* host); /* 1 for /proc/<pid>/maps */
long proc_maps_open(const char* host, long flags);
int proc_status(const char* host); /* 1 for /proc/<pid>/status */
long proc_status_open(const char* host, long flags);
long proc_stat(struct kstat* st);
long proc_statx(struct kstatx* stx);

/* l2s.c */
int l2s_stat(const char* host, struct kstat* st);
int l2s_statx(const char* host, long flags, long mask, struct kstatx* stx);
long l2s_link(const char* old, const char* new);
long l2s_unlinked(const char* host);

/* elf.c */
__attribute__((noreturn)) void load_and_run(long* sp);
