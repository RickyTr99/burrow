/*
 * SysV shared memory (shmget/shmat/shmdt/shmctl), which Android's kernel
 * refuses to apps: each segment is a file in /tmp/.burrow-ipc of the rootfs,
 * named by its id, and shmat() maps it shared. Keyed segments use the key as
 * the id; IPC_PRIVATE ones a random id.
 *
 * IPC_RMID renames the file to r<id>: attaching it stays possible for a while
 * (X clients mark segments removed before the server attaches them), and
 * shmget() deletes the removed files older than a minute. Mappings outlive
 * the file anyway.
 */

#include "burrow.h"

#define NR_getdents64 61
#define NR_getrandom 278
#define IPC_CREAT 01000
#define IPC_EXCL 02000
#define IPC_RMID 0
#define IPC_SET 1
#define IPC_STAT 2
#define SHM_LOCK 11
#define SHM_UNLOCK 12
#define SHM_RDONLY 010000
#define SHM_RND 020000
#define SHM_EXEC 0100000
#define SHMLBA 4096
#define O_RDWR 2
#define MAP_SHARED 0x01
#define REMOVED_LIFETIME 60 /* seconds */

struct ipc64_perm {
    int32_t key;
    uint32_t uid, gid, cuid, cgid, mode;
    uint16_t seq, pad;
    unsigned long unused[2];
};

struct shmid64_ds {
    struct ipc64_perm perm;
    size_t segsz;
    long atime, dtime, ctime;
    int32_t cpid, lpid;
    unsigned long nattch, unused[2];
};

/* @out = the directory, plus "/" @prefix @id if @prefix is not 0. */
static long ipc_path(char* out, const char* prefix, long id) {
    if (cfg.root_length + 64 >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(out, cfg.root, cfg.root_length);
    char* end = out + cfg.root_length;
    memcpy(end, "/tmp/.burrow-ipc", 17);
    if (prefix == 0) return 0;
    end += 16;
    *end++ = '/';
    long p = length_of(prefix);
    memcpy(end, prefix, p);
    format_unsigned(end + p, (unsigned long) id);
    return 0;
}

/* Deletes the removed segments older than REMOVED_LIFETIME. */
static void collect_removed(void) {
    char dir_path[PATH_MAX], path[PATH_MAX], entries[2048];
    ipc_path(dir_path, 0, 0);
    long dir = sys(NR_openat, AT_FDCWD, dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dir < 0) return;
    long now[2] = {0, 0}, n;
    sys(113 /* clock_gettime */, 0 /* CLOCK_REALTIME */, now, 0, 0);
    while ((n = sys(NR_getdents64, dir, entries, sizeof(entries), 0)) > 0) {
        for (long at = 0; at < n;) {
            uint16_t length = *(uint16_t*) (entries + at + 16);
            const char* name = entries + at + 19;
            at += length;
            if (name[0] != 'r') continue;
            const char* digits = name + 1;
            long id = (long) parse_unsigned(&digits);
            struct kstat st;
            ipc_path(path, "r", id);
            if (sys6(NR_newfstatat, AT_FDCWD, (long) path, (long) &st, AT_SYMLINK_NOFOLLOW, 0, 0) == 0 &&
                st.times[4] + REMOVED_LIFETIME < now[0])
                sys(NR_unlinkat, AT_FDCWD, path, 0, 0);
        }
    }
    sys(NR_close, dir, 0, 0, 0);
}

static long shm_get(long key, size_t size, long flags) {
    char path[PATH_MAX];
    long mode = (flags & 0777) | 0600;
    ipc_path(path, 0, 0);
    sys(NR_mkdirat, AT_FDCWD, path, 0700, 0);
    collect_removed();
    if (key != 0) {
        /* shortcut: two keys equal but for the sign bit share a segment; store the key if that ever matters. */
        long id = key & 0x7fffffff;
        ipc_path(path, "", id);
        long fd = -ENOENT;
        if (flags & IPC_CREAT) {
            fd = sys(NR_openat, AT_FDCWD, path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, mode);
            if (fd >= 0) {
                long r = size == 0 ? -EINVAL : sys(46 /* ftruncate */, fd, size, 0, 0);
                sys(NR_close, fd, 0, 0, 0);
                if (r < 0) sys(NR_unlinkat, AT_FDCWD, path, 0, 0);
                return r < 0 ? r : id;
            }
            if (fd != -17 /* EEXIST */ || (flags & IPC_EXCL)) return fd;
        }
        fd = sys(NR_openat, AT_FDCWD, path, O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0);
        if (fd < 0) return fd;
        struct kstat st;
        long r = sys(NR_fstat, fd, &st, 0, 0);
        sys(NR_close, fd, 0, 0, 0);
        if (r < 0) return r;
        return (size_t) st.size < size ? -EINVAL : id;
    }
    if (size == 0) return -EINVAL;
    for (int tries = 0; tries < 16; tries++) {
        uint32_t id;
        if (sys(NR_getrandom, &id, sizeof(id), 0, 0) != sizeof(id)) return -ENOMEM;
        id &= 0x7fffffff;
        ipc_path(path, "", id);
        long fd = sys(NR_openat, AT_FDCWD, path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, mode);
        if (fd == -17 /* EEXIST */) continue;
        if (fd < 0) return fd;
        long r = sys(46 /* ftruncate */, fd, size, 0, 0);
        sys(NR_close, fd, 0, 0, 0);
        return r < 0 ? r : (long) id;
    }
    return -28 /* ENOSPC */;
}

/* Opens segment @id, removed or not. */
static long shm_open(long id, long flags) {
    char path[PATH_MAX];
    if (id < 0) return -EINVAL;
    ipc_path(path, "", id);
    long fd = sys(NR_openat, AT_FDCWD, path, flags | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd != -ENOENT) return fd;
    ipc_path(path, "r", id);
    fd = sys(NR_openat, AT_FDCWD, path, flags | O_CLOEXEC | O_NOFOLLOW, 0);
    return fd == -ENOENT ? -EINVAL : fd;
}

static long shm_at(long id, uintptr_t addr, long flags) {
    long fd = shm_open(id, flags & SHM_RDONLY ? O_RDONLY : O_RDWR);
    if (fd < 0) return fd;
    struct kstat st;
    long r = sys(NR_fstat, fd, &st, 0, 0);
    if (r >= 0) {
        if (flags & SHM_RND) addr &= ~(uintptr_t) (SHMLBA - 1);
        long prot = PROT_READ | (flags & SHM_RDONLY ? 0 : PROT_WRITE) | (flags & SHM_EXEC ? PROT_EXEC : 0);
        if (addr & (SHMLBA - 1)) r = -EINVAL;
        else r = sys6(NR_mmap, (long) addr, st.size, prot, MAP_SHARED | (addr ? MAP_FIXED : 0), fd, 0);
    }
    sys(NR_close, fd, 0, 0, 0);
    return r;
}

static int is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

static uintptr_t parse_hex(const char** s) {
    uintptr_t v = 0;
    for (; is_hex(**s); (*s)++) v = v * 16 + (uintptr_t) (**s <= '9' ? **s - '0' : **s - 'a' + 10);
    return v;
}

/* Unmaps the segment attached at @addr: the mappings of the same file that
 * follow it in /proc/self/maps without gaps (mprotect() may have split it). */
static long shm_dt(uintptr_t addr) {
    long fd = sys(NR_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return fd;
    char buf[4096], file[PATH_MAX];
    long have = 0, n;
    uintptr_t start = 0, end = 0;
    int found = 0;
    file[0] = 0;
    while ((n = sys(NR_read, fd, buf + have, sizeof(buf) - have, 0)) > 0 || have > 0) {
        have += n > 0 ? n : 0;
        long eol = 0;
        while (eol < have && buf[eol] != '\n') eol++;
        if (eol == have && n > 0 && have < (long) sizeof(buf)) continue;
        buf[eol < have ? eol : have - 1] = 0;
        /* "start-end perms offset dev inode   path" */
        const char* p = buf;
        uintptr_t s = parse_hex(&p);
        p++;
        uintptr_t e = parse_hex(&p);
        for (int field = 0; field < 4 && *p; field++) {
            while (*p == ' ') p++;
            while (*p && *p != ' ') p++;
        }
        while (*p == ' ') p++;
        if (!found && s == addr && length_of(p) < PATH_MAX && starts_with(p, cfg.root)) {
            found = 1;
            start = s;
            end = e;
            copy(file, PATH_MAX, p);
        } else if (found) {
            if (s != end || !same(p, file)) break;
            end = e;
        }
        long next = eol < have ? eol + 1 : have;
        memmove(buf, buf + next, have - next);
        have -= next;
        if (n <= 0 && have == 0) break;
    }
    sys(NR_close, fd, 0, 0, 0);
    if (!found) return -EINVAL;
    return sys(NR_munmap, start, end - start, 0, 0);
}

static long shm_ctl(long id, long cmd, struct shmid64_ds* buf) {
    char path[PATH_MAX], removed[PATH_MAX];
    switch (cmd & ~0x100 /* IPC_64 */) {
    case IPC_RMID:
        ipc_path(path, "", id);
        ipc_path(removed, "r", id);
        if (id < 0 || sys6(NR_renameat2, AT_FDCWD, (long) path, AT_FDCWD, (long) removed, 0, 0) < 0) return -EINVAL;
        return 0;
    case IPC_STAT: {
        long fd = shm_open(id, O_RDONLY);
        if (fd < 0) return fd;
        struct kstat st;
        long r = sys(NR_fstat, fd, &st, 0, 0);
        sys(NR_close, fd, 0, 0, 0);
        if (r < 0) return r;
        memset(buf, 0, sizeof(*buf));
        buf->perm.uid = buf->perm.cuid = cfg.ids[EUID];
        buf->perm.gid = buf->perm.cgid = cfg.ids[EGID];
        buf->perm.mode = st.mode & 0777;
        buf->segsz = (size_t) st.size;
        buf->atime = st.times[0];
        buf->ctime = st.times[4];
        buf->nattch = 1; /* shortcut: attachments are not counted */
        return 0;
    }
    case IPC_SET:
    case SHM_LOCK:
    case SHM_UNLOCK: {
        long fd = shm_open(id, O_RDONLY);
        if (fd < 0) return fd;
        sys(NR_close, fd, 0, 0, 0);
        return 0;
    }
    default: return -EINVAL;
    }
}

long emulate_sysv(long nr, const uint64_t* x) {
    switch (nr) {
    case NR_shmget: return shm_get((long) (int32_t) x[0], (size_t) x[1], (long) x[2]);
    case NR_shmat: return shm_at((long) (int32_t) x[0], (uintptr_t) x[1], (long) x[2]);
    case NR_shmdt: return shm_dt((uintptr_t) x[0]);
    case NR_shmctl: return shm_ctl((long) (int32_t) x[0], (long) x[1], (struct shmid64_ds*) x[2]);
    default: return -ENOSYS;
    }
}
