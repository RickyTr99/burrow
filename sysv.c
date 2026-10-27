/*
 * SysV IPC, which Android's kernel refuses to apps: each object is a file in
 * /tmp/.burrow-ipc of the rootfs, named by its id. Keyed objects use the key
 * as the id; IPC_PRIVATE ones a random id.
 *
 * Shared memory segments (shmget/shmat/shmdt/shmctl): shmat() maps the file.
 *
 * IPC_RMID renames the file to r<id>: attaching it stays possible for a while
 * (X clients mark segments removed before the server attaches them), and
 * shmget() deletes the removed files older than a minute. Mappings outlive
 * the file anyway.
 *
 * Semaphore sets and message queues (s<id>, q<id>): the file is mapped shared
 * for each call; a futex guards it, and waiters sleep on its change counter.
 * IPC_RMID unlinks it and marks it removed, which wakes waiters with EIDRM.
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
            /* Removed segments, and objects of a process killed while making them. */
            if (name[0] != 'r' && name[0] != 't') continue;
            const char* digits = name + 1;
            long id = (long) parse_unsigned(&digits);
            struct kstat st;
            ipc_path(path, name[0] == 'r' ? "r" : "t", id);
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

/* -- Semaphores and message queues ---------------------------------------------- */

#define NR_futex 98
#define NR_clock_gettime 113
#define FUTEX_WAIT 0
#define FUTEX_WAKE 1
#define FUTEX_WAIT_BITSET 9
#define RENAME_NOREPLACE 1
#define IPC_NOWAIT 04000
#define IPC_INFO 3
#define EAGAIN 11
#define EEXIST 17
#define EFBIG 27
#define ENOMSG 42
#define EIDRM 43
#define ETIMEDOUT 110
#define GETPID 11
#define GETVAL 12
#define GETALL 13
#define GETNCNT 14
#define GETZCNT 15
#define SETVAL 16
#define SETALL 17
#define SEM_STAT 18
#define SEM_INFO 19
#define SEM_STAT_ANY 20
#define MSG_STAT 11
#define MSG_INFO 12
#define MSG_STAT_ANY 13
#define MSG_NOERROR 010000
#define MSG_EXCEPT 020000
#define MSG_COPY 040000
/* Linux's limits, but SEMMSL: GETALL and SETALL copy through the stack. */
#define SEMMSL 4096
#define SEMOPM 500
#define SEMVMX 32767
#define MSGMAX 8192
#define MSGMNB 16384
#define QUEUE_BYTES_MAX 65536 /* msg_qbytes: a queue's file has room for that much */
#define MAGIC_SEM 0x316d6553u
#define MAGIC_QUEUE 0x31657551u

/* The start of a set's or a queue's file. */
struct ipc_head {
    uint32_t magic, lock, changes, waiters;
    int32_t removed, key;
    uint32_t mode, uid, gid, cuid, cgid, pad;
    int64_t ctime;
    uint64_t size; /* of the file */
};

struct sem_set {
    struct ipc_head head;
    int64_t otime;
    uint64_t count;
    struct {
        int32_t value, pid;
        uint32_t waiting_more, waiting_zero; /* semncnt, semzcnt */
    } sems[];
};

struct queue {
    struct ipc_head head;
    int64_t stime, rtime;
    int32_t lspid, lrpid;
    uint64_t bytes, count, limit; /* text bytes, messages, msg_qbytes */
    uint64_t used, capacity;      /* of the area */
    char area[];                  /* the messages: type, length, text padded to 8 bytes */
};

struct sembuf {
    uint16_t num;
    int16_t op, flags;
};

struct semid64_ds {
    struct ipc64_perm perm;
    long otime, ctime;
    unsigned long nsems, unused[2];
};

struct msqid64_ds {
    struct ipc64_perm perm;
    long stime, rtime, ctime;
    unsigned long cbytes, qnum, qbytes;
    int32_t lspid, lrpid;
    unsigned long unused[2];
};

struct ktimespec {
    long sec, nsec;
};

static long now(void) {
    struct ktimespec t = {0, 0};
    sys(NR_clock_gettime, 0 /* CLOCK_REALTIME */, &t, 0, 0);
    return t.sec;
}

static int failed(long r) { return r < 0 && r > -4096; }

/* Makes the object of @key (0: IPC_PRIVATE) under @prefix, @size bytes, its
 * head and the rest set by @init; or finds it. Its id, or an error. */
static long ipc_get(const char* prefix, long key, long flags, long size, uint32_t magic,
                    void (*init)(struct ipc_head*, long), long arg) {
    char path[PATH_MAX], temp[PATH_MAX];
    ipc_path(path, 0, 0);
    sys(NR_mkdirat, AT_FDCWD, path, 0700, 0);
    collect_removed();
    /* shortcut: two keys equal but for the sign bit share an object, as with shm. */
    long id = key & 0x7fffffff;
    if (key != 0) {
        struct kstat st;
        ipc_path(path, prefix, id);
        long r = sys6(NR_newfstatat, AT_FDCWD, (long) path, (long) &st, AT_SYMLINK_NOFOLLOW, 0, 0);
        if (r == 0) return (flags & IPC_CREAT) && (flags & IPC_EXCL) ? -EEXIST : id;
        if (r != -ENOENT) return r;
        if (!(flags & IPC_CREAT)) return -ENOENT;
    }
    if (size == 0) return -EINVAL;
    for (int tries = 0; tries < 16; tries++) {
        uint32_t random;
        if (sys(NR_getrandom, &random, sizeof(random), 0, 0) != sizeof(random)) return -ENOMEM;
        random &= 0x7fffffff;
        if (key == 0) id = random;
        /* Made under a temporary name, then given its own: nobody sees it half made. */
        ipc_path(temp, "t", random);
        long fd = sys(NR_openat, AT_FDCWD, temp, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0600);
        if (fd == -EEXIST) continue;
        if (fd < 0) return fd;
        long r = sys(46 /* ftruncate */, fd, size, 0, 0);
        long a = r < 0 ? r : sys6(NR_mmap, 0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        sys(NR_close, fd, 0, 0, 0);
        if (failed(a)) {
            sys(NR_unlinkat, AT_FDCWD, temp, 0, 0);
            return a;
        }
        struct ipc_head* h = (struct ipc_head*) a;
        h->key = (int32_t) key;
        h->mode = (uint32_t) (flags & 0777);
        h->uid = h->cuid = cfg.ids[EUID];
        h->gid = h->cgid = cfg.ids[EGID];
        h->ctime = now();
        h->size = (uint64_t) size;
        init(h, arg);
        h->magic = magic;
        sys(NR_munmap, a, size, 0, 0);
        ipc_path(path, prefix, id);
        r = sys6(NR_renameat2, AT_FDCWD, (long) temp, AT_FDCWD, (long) path, RENAME_NOREPLACE, 0);
        if (r == 0) return id;
        sys(NR_unlinkat, AT_FDCWD, temp, 0, 0);
        if (r != -EEXIST) return r;
        if (key != 0) return flags & IPC_EXCL ? -EEXIST : id; /* made meanwhile */
    }
    return -28 /* ENOSPC */;
}

/* Maps object @id under @prefix: its head's address, or an error. */
static long ipc_map(const char* prefix, long id, uint32_t magic) {
    char path[PATH_MAX];
    if (id < 0) return -EINVAL;
    ipc_path(path, prefix, id);
    long fd = sys(NR_openat, AT_FDCWD, path, O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) return fd == -ENOENT ? -EINVAL : fd;
    struct kstat st;
    long a = sys(NR_fstat, fd, &st, 0, 0);
    if (a == 0) {
        a = st.size < (int64_t) sizeof(struct ipc_head)
                ? -EINVAL
                : sys6(NR_mmap, 0, st.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    sys(NR_close, fd, 0, 0, 0);
    if (failed(a)) return a;
    struct ipc_head* h = (struct ipc_head*) a;
    if (h->magic != magic || h->size != (uint64_t) st.size) {
        sys(NR_munmap, a, st.size, 0, 0);
        return -EINVAL;
    }
    return a;
}

static void ipc_unmap(struct ipc_head* h) { sys(NR_munmap, h, h->size, 0, 0); }

static void ipc_lock(struct ipc_head* h) {
    uint32_t unlocked = 0;
    if (__atomic_compare_exchange_n(&h->lock, &unlocked, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return;
    while (__atomic_exchange_n(&h->lock, 2, __ATOMIC_ACQUIRE) != 0) sys(NR_futex, &h->lock, FUTEX_WAIT, 2, 0);
}

static void ipc_unlock(struct ipc_head* h) {
    if (__atomic_exchange_n(&h->lock, 0, __ATOMIC_RELEASE) == 2) sys(NR_futex, &h->lock, FUTEX_WAKE, 1, 0);
}

/* Under the lock: wakes the waiters. */
static void ipc_changed(struct ipc_head* h) {
    __atomic_add_fetch(&h->changes, 1, __ATOMIC_RELEASE);
    if (h->waiters) sys(NR_futex, &h->changes, FUTEX_WAKE, 0x7fffffff, 0);
}

/* Under the lock: sleeps until a change, or the CLOCK_MONOTONIC @deadline if
 * not 0. 0, -EINTR, or -EAGAIN once the deadline passed. */
static long ipc_wait(struct ipc_head* h, const struct ktimespec* deadline) {
    uint32_t seen = h->changes;
    h->waiters++;
    ipc_unlock(h);
    long r = sys6(NR_futex, (long) &h->changes, FUTEX_WAIT_BITSET, seen, (long) deadline, 0, (long) 0xffffffffu);
    ipc_lock(h);
    h->waiters--;
    return r == -EINTR ? -EINTR : r == -ETIMEDOUT ? -EAGAIN : 0;
}

/* Under the lock: IPC_RMID. */
static long ipc_remove(struct ipc_head* h, const char* prefix, long id) {
    char path[PATH_MAX];
    ipc_path(path, prefix, id);
    long r = sys(NR_unlinkat, AT_FDCWD, path, 0, 0);
    if (r < 0) return r == -ENOENT ? -EINVAL : r;
    h->removed = 1;
    ipc_changed(h);
    return 0;
}

static void ipc_stat(const struct ipc_head* h, struct ipc64_perm* perm) {
    memset(perm, 0, sizeof(*perm));
    perm->key = h->key;
    perm->uid = h->uid, perm->gid = h->gid, perm->cuid = h->cuid, perm->cgid = h->cgid;
    perm->mode = h->mode;
}

static void ipc_set(struct ipc_head* h, const struct ipc64_perm* perm) {
    h->uid = perm->uid, h->gid = perm->gid;
    h->mode = perm->mode & 0777;
    h->ctime = now();
}

/* The CLOCK_MONOTONIC time @timeout from now, in @deadline. */
static long deadline_of(const struct ktimespec* timeout, struct ktimespec* deadline) {
    if (timeout->sec < 0 || timeout->nsec < 0 || timeout->nsec >= 1000000000) return -EINVAL;
    sys(NR_clock_gettime, 1 /* CLOCK_MONOTONIC */, deadline, 0, 0);
    deadline->sec += timeout->sec;
    deadline->nsec += timeout->nsec;
    if (deadline->nsec >= 1000000000) deadline->sec++, deadline->nsec -= 1000000000;
    return 0;
}

static void init_sem(struct ipc_head* h, long count) { ((struct sem_set*) h)->count = (uint64_t) count; }

static long sem_get(long key, long count, long flags) {
    if (count < 0 || count > SEMMSL) return -EINVAL;
    long size = count == 0 ? 0 : (long) (sizeof(struct sem_set) + count * sizeof(((struct sem_set*) 0)->sems[0]));
    long id = ipc_get("s", key, flags, size, MAGIC_SEM, init_sem, count);
    if (id < 0 || key == 0) return id;
    long a = ipc_map("s", id, MAGIC_SEM);
    if (failed(a)) return a;
    struct sem_set* s = (struct sem_set*) a;
    long r = (uint64_t) count > s->count ? -EINVAL : id;
    ipc_unmap(&s->head);
    return r;
}

/* semop(), semtimedop(): the @n operations all at once, or none.
 * shortcut: SEM_UNDO is not kept, so a process killed holding a semaphore
 * leaves it taken; keep undo lists per process if a program needs them. */
static long sem_op(long id, const struct sembuf* guest_ops, long n, const struct ktimespec* timeout) {
    struct sembuf ops[SEMOPM];
    struct ktimespec deadline;
    if (n <= 0) return -EINVAL;
    if (n > SEMOPM) return -E2BIG;
    if (guest_ops == 0) return -EFAULT;
    /* Guest memory is read and written outside the lock: a bad pointer must not die holding it. */
    memcpy(ops, guest_ops, n * sizeof(*ops));
    if (timeout != 0) {
        long r = deadline_of(timeout, &deadline);
        if (r < 0) return r;
    }
    long a = ipc_map("s", id, MAGIC_SEM);
    if (failed(a)) return a;
    struct sem_set* s = (struct sem_set*) a;
    long r = 0;
    for (long i = 0; i < n; i++)
        if (ops[i].num >= s->count) r = -EFBIG;
    long pid = sys(NR_getpid, 0, 0, 0, 0);
    ipc_lock(&s->head);
    while (r == 0) {
        if (s->head.removed) {
            r = -EIDRM;
            break;
        }
        long i = 0;
        for (; i < n; i++) {
            int32_t* v = &s->sems[ops[i].num].value;
            if (ops[i].op == 0 ? *v != 0 : *v + ops[i].op < 0) break;
            if (*v + ops[i].op > SEMVMX) {
                r = -ERANGE;
                break;
            }
            *v += ops[i].op;
        }
        if (i == n) {
            int changed = 0;
            for (i = 0; i < n; i++) {
                s->sems[ops[i].num].pid = (int32_t) pid;
                changed |= ops[i].op != 0;
            }
            s->otime = now();
            if (changed) ipc_changed(&s->head);
            break;
        }
        for (long j = i - 1; j >= 0; j--) s->sems[ops[j].num].value -= ops[j].op;
        if (r < 0) break;
        if (ops[i].flags & IPC_NOWAIT) {
            r = -EAGAIN;
            break;
        }
        uint32_t* waiting = ops[i].op == 0 ? &s->sems[ops[i].num].waiting_zero : &s->sems[ops[i].num].waiting_more;
        (*waiting)++;
        r = ipc_wait(&s->head, timeout != 0 ? &deadline : 0);
        (*waiting)--;
    }
    ipc_unlock(&s->head);
    ipc_unmap(&s->head);
    return r;
}

static long sem_ctl(long id, long num, long cmd, uint64_t arg) {
    uint16_t values[SEMMSL];
    cmd &= ~0x100; /* IPC_64 */
    if (cmd == IPC_INFO || cmd == SEM_INFO) {
        /* struct seminfo: semmap, semmni, semmns, semmnu, semmsl, semopm, semume, semusz, semvmx, semaem */
        int32_t info[10] = {32000, 32000, 32000 * SEMMSL, 32000, SEMMSL, SEMOPM, SEMOPM, 20, SEMVMX, SEMVMX};
        if (arg == 0) return -EFAULT;
        memcpy((void*) arg, info, sizeof(info));
        return 0;
    }
    struct semid64_ds ds;
    if ((cmd == SETALL || cmd == IPC_SET || cmd == GETALL || cmd == IPC_STAT || cmd == SEM_STAT ||
         cmd == SEM_STAT_ANY) && arg == 0)
        return -EFAULT;
    if (cmd == IPC_SET) memcpy(&ds, (const void*) arg, sizeof(ds));
    long a = ipc_map("s", id, MAGIC_SEM);
    if (failed(a)) return a;
    struct sem_set* s = (struct sem_set*) a;
    long count = (long) s->count, r = 0;
    if (cmd == SETALL) {
        memcpy(values, (const void*) arg, count * sizeof(*values));
        for (long i = 0; i < count; i++)
            if (values[i] > SEMVMX) r = -ERANGE;
    }
    int one = cmd == GETVAL || cmd == GETPID || cmd == GETNCNT || cmd == GETZCNT || cmd == SETVAL;
    if (one && (num < 0 || num >= count)) r = -EINVAL;
    ipc_lock(&s->head);
    if (r == 0) switch (cmd) {
    case 0 /* IPC_RMID */: r = ipc_remove(&s->head, "s", id); break;
    case IPC_STAT:
    case SEM_STAT:
    case SEM_STAT_ANY:
        memset(&ds, 0, sizeof(ds));
        ipc_stat(&s->head, &ds.perm);
        ds.otime = s->otime;
        ds.ctime = s->head.ctime;
        ds.nsems = s->count;
        r = cmd == IPC_STAT ? 0 : id;
        break;
    case IPC_SET: ipc_set(&s->head, &ds.perm); break;
    case GETVAL: r = s->sems[num].value; break;
    case GETPID: r = s->sems[num].pid; break;
    case GETNCNT: r = s->sems[num].waiting_more; break;
    case GETZCNT: r = s->sems[num].waiting_zero; break;
    case GETALL:
        for (long i = 0; i < count; i++) values[i] = (uint16_t) s->sems[i].value;
        break;
    case SETVAL:
        if ((int) arg < 0 || (int) arg > SEMVMX) {
            r = -ERANGE;
            break;
        }
        s->sems[num].value = (int) arg;
        s->head.ctime = now();
        ipc_changed(&s->head);
        break;
    case SETALL:
        for (long i = 0; i < count; i++) s->sems[i].value = values[i];
        s->head.ctime = now();
        ipc_changed(&s->head);
        break;
    default: r = -EINVAL;
    }
    ipc_unlock(&s->head);
    ipc_unmap(&s->head);
    if (r >= 0 && (cmd == IPC_STAT || cmd == SEM_STAT || cmd == SEM_STAT_ANY)) memcpy((void*) arg, &ds, sizeof(ds));
    if (r >= 0 && cmd == GETALL) memcpy((void*) arg, values, count * sizeof(*values));
    return r;
}

/* Room for QUEUE_BYTES_MAX messages of no text, or for their text. */
#define QUEUE_AREA (24L * QUEUE_BYTES_MAX)

static void init_queue(struct ipc_head* h, long unused) {
    (void) unused;
    struct queue* q = (struct queue*) h;
    q->limit = MSGMNB;
    q->capacity = QUEUE_AREA;
}

static long msg_get(long key, long flags) {
    return ipc_get("q", key, flags, (long) sizeof(struct queue) + QUEUE_AREA, MAGIC_QUEUE, init_queue, 0);
}

static long record_size(uint64_t length) { return 16 + (long) ((length + 7) & ~7ul); }

static long msg_snd(long id, const char* message, long length, long flags) {
    char text[MSGMAX];
    if (length < 0 || length > MSGMAX) return -EINVAL;
    if (message == 0) return -EFAULT;
    long type = *(const long*) message;
    if (type < 1) return -EINVAL;
    memcpy(text, message + 8, length);
    long a = ipc_map("q", id, MAGIC_QUEUE);
    if (failed(a)) return a;
    struct queue* q = (struct queue*) a;
    long r = 0, record = record_size((uint64_t) length);
    long pid = sys(NR_getpid, 0, 0, 0, 0);
    ipc_lock(&q->head);
    for (;;) {
        if (q->head.removed) {
            r = -EIDRM;
            break;
        }
        if (q->bytes + length <= q->limit && q->count + 1 <= q->limit && q->used + record <= q->capacity) {
            char* at = q->area + q->used;
            *(int64_t*) at = type;
            *(uint64_t*) (at + 8) = (uint64_t) length;
            memcpy(at + 16, text, length);
            q->used += record;
            q->bytes += length;
            q->count++;
            q->lspid = (int32_t) pid;
            q->stime = now();
            ipc_changed(&q->head);
            break;
        }
        if (flags & IPC_NOWAIT) {
            r = -EAGAIN;
            break;
        }
        if ((r = ipc_wait(&q->head, 0)) < 0) break;
    }
    ipc_unlock(&q->head);
    ipc_unmap(&q->head);
    return r;
}

static long msg_rcv(long id, char* message, long size, long type, long flags) {
    char text[MSGMAX];
    if (size < 0) return -EINVAL;
    if (flags & MSG_COPY) return -ENOSYS;
    if (message == 0) return -EFAULT;
    long a = ipc_map("q", id, MAGIC_QUEUE);
    if (failed(a)) return a;
    struct queue* q = (struct queue*) a;
    long r = 0, found_type = 0;
    long pid = sys(NR_getpid, 0, 0, 0, 0);
    ipc_lock(&q->head);
    for (;;) {
        if (q->head.removed) {
            r = -EIDRM;
            break;
        }
        long found = -1;
        for (uint64_t at = 0; at < q->used; at += record_size(*(uint64_t*) (q->area + at + 8))) {
            long t = *(int64_t*) (q->area + at);
            int match = type == 0 || (type > 0 ? ((flags & MSG_EXCEPT) ? t != type : t == type) : t <= -type);
            if (!match || (type < 0 && found >= 0 && t >= *(int64_t*) (q->area + found))) continue;
            found = (long) at;
            if (type >= 0) break; /* the first; type < 0 wants the lowest */
        }
        if (found >= 0) {
            char* at = q->area + found;
            long length = (long) *(uint64_t*) (at + 8);
            if (length > size && !(flags & MSG_NOERROR)) {
                r = -E2BIG;
                break;
            }
            found_type = *(int64_t*) at;
            r = length < size ? length : size;
            memcpy(text, at + 16, r);
            long record = record_size((uint64_t) length);
            memmove(at, at + record, q->used - found - record);
            q->used -= record;
            q->bytes -= length;
            q->count--;
            q->lrpid = (int32_t) pid;
            q->rtime = now();
            ipc_changed(&q->head);
            break;
        }
        if (flags & IPC_NOWAIT) {
            r = -ENOMSG;
            break;
        }
        if ((r = ipc_wait(&q->head, 0)) < 0) break;
    }
    ipc_unlock(&q->head);
    ipc_unmap(&q->head);
    if (r >= 0) {
        *(long*) message = found_type;
        memcpy(message + 8, text, r);
    }
    return r;
}

static long msg_ctl(long id, long cmd, void* buf) {
    cmd &= ~0x100; /* IPC_64 */
    if (cmd == IPC_INFO || cmd == MSG_INFO) {
        /* struct msginfo: msgpool, msgmap, msgmax, msgmnb, msgmni, msgssz, msgtql (int), msgseg (short) */
        int32_t info[7] = {32000 * (MSGMNB / 1024), 32000, MSGMAX, MSGMNB, 32000, 16, 32000};
        uint16_t segments = 0xffff;
        if (buf == 0) return -EFAULT;
        memcpy(buf, info, sizeof(info));
        memcpy((char*) buf + sizeof(info), &segments, sizeof(segments));
        return 0;
    }
    struct msqid64_ds ds;
    if (cmd != 0 && buf == 0) return -EFAULT;
    if (cmd == IPC_SET) {
        memcpy(&ds, buf, sizeof(ds));
        if (ds.qbytes > QUEUE_BYTES_MAX) return -EPERM; /* more than its file has room for */
    }
    long a = ipc_map("q", id, MAGIC_QUEUE);
    if (failed(a)) return a;
    struct queue* q = (struct queue*) a;
    long r = 0;
    ipc_lock(&q->head);
    switch (cmd) {
    case 0 /* IPC_RMID */: r = ipc_remove(&q->head, "q", id); break;
    case IPC_STAT:
    case MSG_STAT:
    case MSG_STAT_ANY:
        memset(&ds, 0, sizeof(ds));
        ipc_stat(&q->head, &ds.perm);
        ds.stime = q->stime, ds.rtime = q->rtime, ds.ctime = q->head.ctime;
        ds.cbytes = q->bytes, ds.qnum = q->count, ds.qbytes = q->limit;
        ds.lspid = q->lspid, ds.lrpid = q->lrpid;
        r = cmd == IPC_STAT ? 0 : id;
        break;
    case IPC_SET:
        ipc_set(&q->head, &ds.perm);
        q->limit = ds.qbytes;
        ipc_changed(&q->head); /* senders may fit now */
        break;
    default: r = -EINVAL;
    }
    ipc_unlock(&q->head);
    ipc_unmap(&q->head);
    if (r >= 0 && cmd != 0 && cmd != IPC_SET) memcpy(buf, &ds, sizeof(ds));
    return r;
}

long emulate_sysv(long nr, const uint64_t* x) {
    switch (nr) {
    case NR_shmget: return shm_get((long) (int32_t) x[0], (size_t) x[1], (long) x[2]);
    case NR_shmat: return shm_at((long) (int32_t) x[0], (uintptr_t) x[1], (long) x[2]);
    case NR_shmdt: return shm_dt((uintptr_t) x[0]);
    case NR_shmctl: return shm_ctl((long) (int32_t) x[0], (long) x[1], (struct shmid64_ds*) x[2]);
    case NR_semget: return sem_get((long) (int32_t) x[0], (long) (int) x[1], (long) x[2]);
    case NR_semop: return sem_op((long) (int32_t) x[0], (const struct sembuf*) x[1], (long) x[2], 0);
    case NR_semtimedop:
        return sem_op((long) (int32_t) x[0], (const struct sembuf*) x[1], (long) x[2], (const struct ktimespec*) x[3]);
    case NR_semctl: return sem_ctl((long) (int32_t) x[0], (long) (int) x[1], (long) x[2], x[3]);
    case NR_msgget: return msg_get((long) (int32_t) x[0], (long) x[1]);
    case NR_msgsnd: return msg_snd((long) (int32_t) x[0], (const char*) x[1], (long) x[2], (long) x[3]);
    case NR_msgrcv: return msg_rcv((long) (int32_t) x[0], (char*) x[1], (long) x[2], (long) x[3], (long) x[4]);
    case NR_msgctl: return msg_ctl((long) (int32_t) x[0], (long) x[1], (void*) x[2]);
    default: return -ENOSYS;
    }
}
