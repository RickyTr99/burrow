/*
 * Hard links, which Android's SELinux policy refuses to apps, as symlinks in
 * proot's link2symlink format, so rootfses proot has written keep working:
 *
 *   name                      -> <dir>/.l2s.name0001         (one per link)
 *   <dir>/.l2s.name0001       -> <dir>/.l2s.name0001.0003    (the intermediate)
 *   <dir>/.l2s.name0001.0003                                 (the file; 3 links)
 *
 * Link contents are host paths. A link shows as the file itself to stat(),
 * with the count as its number of links.
 *
 * New chains keep their intermediate and file in the rootfs's /.l2s, named
 * after the inode, so a link never adds or renames entries in the directory
 * linked from: copies with hard links (cp -al, rsync -H, pressure-vessel)
 * walk it as they link. Where the rootfs is another filesystem, the chain
 * stays beside the file, as proot made it.
 */

#include "burrow.h"

#define PREFIX ".l2s."
#define STORE ".l2s" /* in the rootfs's root, hidden from its listing */

static long read_link(const char* host, char* out) {
    long n = sys(NR_readlinkat, AT_FDCWD, host, out, PATH_MAX - 1);
    if (n >= 0) out[n] = 0;
    return n;
}

static const char* base_name(const char* p) {
    const char* b = p;
    for (; *p; p++)
        if (*p == '/') b = p + 1;
    return b;
}

int l2s_target(const char* t) {
    return t[0] == '/' && starts_with(base_name(t), PREFIX);
}

/* The intermediate and file of the faked hard link @host, if it is one. */
static int resolve_link(const char* host, char* intermediate, char* final) {
    if (read_link(host, intermediate) <= 0 || !l2s_target(intermediate)) return 0;
    long n = read_link(intermediate, final);
    return n > 5 && final[n - 5] == '.';
}

static long count_of(const char* final) {
    const char* digits = final + length_of(final) - 4;
    return (long) parse_unsigned(&digits);
}

/* @final with its count set to @count, into @out. */
static void with_count(const char* final, long count, char* out) {
    long n = length_of(final);
    memcpy(out, final, n + 1);
    for (int i = 1; i <= 4; i++, count /= 10) out[n - i] = (char) ('0' + count % 10);
}

int l2s_file(const char* host, char* final) {
    char intermediate[PATH_MAX];
    return resolve_link(host, intermediate, final);
}

static int is_root(long dirfd) {
    struct kstat dir, root;
    return sys(NR_fstat, dirfd, (long) &dir, 0, 0) == 0 &&
           sys(NR_newfstatat, AT_FDCWD, (long) cfg.root, (long) &root, 0) == 0 && dir.dev == root.dev &&
           dir.ino == root.ino;
}

/* The entries of faked hard links among the @size bytes getdents64() read
 * from @dirfd into @buf, typed as the files they are: programs trust d_type
 * (pressure-vessel reads every DT_LNK one, crashing on its NULL target). As
 * readlink() tells them apart: a link to an intermediate, not to a file.
 * Drops the store from the rootfs's root; returns the bytes left. */
long l2s_dirents(long dirfd, char* buf, long size) {
    char target[PATH_MAX];
    for (long at = 0, next; at < size; at = next) {
        long reclen = *(uint16_t*) (buf + at + 16);
        next = at + reclen;
        if (same(buf + at + 19, STORE) && is_root(dirfd)) {
            memmove(buf + at, buf + next, size - next);
            size -= reclen;
            next = at;
            continue;
        }
        char* type = buf + at + 18;
        if (*type != 10 /* DT_LNK */) continue;
        long n = sys(NR_readlinkat, dirfd, (long) (buf + at + 19), (long) target, PATH_MAX - 1);
        if (n <= 5) continue;
        target[n] = 0;
        if (l2s_target(target) && target[n - 5] != '.') *type = 8 /* DT_REG */;
    }
    return size;
}

/* The chain whose intermediate or file @host is, which readdir shows: a copy
 * of the directory with hard links (pressure-vessel's) links them as files,
 * and making one a link of its own would break the chain. */
static int resolve_member(const char* host, char* intermediate, char* final) {
    long n = length_of(host);
    struct kstat st;
    if (!starts_with(base_name(host), PREFIX) || n + 1 > PATH_MAX) return 0;
    long m = read_link(host, final);
    if (m > 5 && l2s_target(final) && final[m - 5] == '.') { /* the intermediate */
        memcpy(intermediate, host, n + 1);
        return sys(NR_newfstatat, AT_FDCWD, final, &st, AT_SYMLINK_NOFOLLOW) == 0 && (st.mode & S_IFMT) == S_IFREG;
    }
    if (n <= 5 || host[n - 5] != '.') return 0; /* the file: its intermediate is its name without the count */
    memcpy(intermediate, host, n - 5);
    intermediate[n - 5] = 0;
    if (read_link(intermediate, final) != n || !same(final, host)) return 0;
    return 1;
}

int l2s_stat(const char* host, struct kstat* st) {
    char intermediate[PATH_MAX], final[PATH_MAX];
    if (!resolve_link(host, intermediate, final)) return 0;
    if (sys(NR_newfstatat, AT_FDCWD, final, st, AT_SYMLINK_NOFOLLOW) < 0) return 0;
    st->nlink = (uint32_t) count_of(final);
    return 1;
}

int l2s_statx(const char* host, long flags, long mask, struct kstatx* stx) {
    char intermediate[PATH_MAX], final[PATH_MAX];
    if (!resolve_link(host, intermediate, final)) return 0;
    if (sys6(NR_statx, AT_FDCWD, (long) final, flags | AT_SYMLINK_NOFOLLOW, mask, (long) stx, 0) < 0) return 0;
    stx->nlink = (uint32_t) count_of(final);
    return 1;
}

long l2s_unlinked(const char* host) {
    char intermediate[PATH_MAX], final[PATH_MAX], next[PATH_MAX];
    struct kstat st;
    if (sys(NR_newfstatat, AT_FDCWD, host, &st, AT_SYMLINK_NOFOLLOW) < 0 || (st.mode & S_IFMT) != S_IFLNK) return 0;
    if (!resolve_link(host, intermediate, final)) return 0;
    long count = count_of(final) - 1;
    long r;
    if (count > 0) {
        with_count(final, count, next);
        if ((r = sys(NR_renameat, AT_FDCWD, final, AT_FDCWD, next)) < 0) return r;
        sys(NR_unlinkat, AT_FDCWD, intermediate, 0, 0);
        return sys(NR_symlinkat, next, AT_FDCWD, intermediate, 0);
    }
    sys(NR_unlinkat, AT_FDCWD, intermediate, 0, 0);
    return sys(NR_unlinkat, AT_FDCWD, final, 0, 0);
}

/* Moves @old to the file of a new chain named after @name in the directory
 * of the first @dir_length bytes of @dir. */
static long new_chain(const char* old, const char* dir, long dir_length, const char* name, char* intermediate,
                      char* final) {
    long n = dir_length + (long) sizeof(PREFIX) - 1 + length_of(name);
    if (n + 10 >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(intermediate, dir, dir_length);
    memcpy(intermediate + dir_length, PREFIX, sizeof(PREFIX) - 1);
    memcpy(intermediate + dir_length + sizeof(PREFIX) - 1, name, length_of(name));
    /* The first free suffix; a dangling intermediate counts as free. */
    for (long suffix = 1;; suffix++) {
        if (suffix == 1000) return -EPERM;
        memcpy(intermediate + n, "0000", 5);
        with_count(intermediate, suffix, intermediate);
        if (sys(NR_faccessat, AT_FDCWD, (long) intermediate, 0, 0) == -ENOENT) break;
    }
    memcpy(final, intermediate, n + 4);
    memcpy(final + n + 4, ".0002", 6);
    return sys(NR_renameat, AT_FDCWD, (long) old, AT_FDCWD, (long) final);
}

long l2s_link(const char* old, const char* new) {
    char intermediate[PATH_MAX], final[PATH_MAX], next[PATH_MAX];
    struct kstat st;
    long r = sys(NR_newfstatat, AT_FDCWD, old, &st, AT_SYMLINK_NOFOLLOW);
    if (r < 0) return r;
    if ((st.mode & S_IFMT) == S_IFDIR) return -EPERM;
    if (((st.mode & S_IFMT) == S_IFLNK && resolve_link(old, intermediate, final)) ||
        resolve_member(old, intermediate, final)) {
        with_count(final, count_of(final) + 1, next);
        if ((r = sys(NR_renameat, AT_FDCWD, final, AT_FDCWD, next)) < 0) return r;
        sys(NR_unlinkat, AT_FDCWD, intermediate, 0, 0);
        if ((r = sys(NR_symlinkat, next, AT_FDCWD, intermediate, 0)) < 0) return r;
    } else {
        char store[PATH_MAX], ino[24];
        long n = cfg.root_length + (long) sizeof("/" STORE "/") - 1;
        format_unsigned(ino, st.ino);
        if (n < PATH_MAX) {
            memcpy(store, cfg.root, cfg.root_length);
            memcpy(store + cfg.root_length, "/" STORE "/", n - cfg.root_length + 1);
            r = new_chain(old, store, n, ino, intermediate, final);
            if (r == -ENOENT && sys(NR_mkdirat, AT_FDCWD, store, 0700, 0) == 0)
                r = new_chain(old, store, n, ino, intermediate, final);
        }
        if (n >= PATH_MAX || r == -EXDEV || r == -ENOENT || r == -EACCES)
            r = new_chain(old, old, base_name(old) - old, base_name(old), intermediate, final);
        if (r < 0) return r;
        if ((r = sys(NR_symlinkat, final, AT_FDCWD, intermediate, 0)) < 0 ||
            (r = sys(NR_symlinkat, intermediate, AT_FDCWD, old, 0)) < 0) {
            sys(NR_unlinkat, AT_FDCWD, intermediate, 0, 0);
            sys(NR_renameat, AT_FDCWD, final, AT_FDCWD, old);
            return r;
        }
    }
    r = sys(NR_symlinkat, intermediate, AT_FDCWD, new, 0);
    if (r < 0) l2s_unlinked(old);
    return r;
}
