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
 */

#include "burrow.h"

#define PREFIX ".l2s."

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

/* The intermediate and file of the faked hard link @host, if it is one. */
static int resolve_link(const char* host, char* intermediate, char* final) {
    if (read_link(host, intermediate) <= 0 || intermediate[0] != '/') return 0;
    if (!starts_with(base_name(intermediate), PREFIX)) return 0;
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

long l2s_link(const char* old, const char* new) {
    char intermediate[PATH_MAX], final[PATH_MAX], next[PATH_MAX];
    struct kstat st;
    long r = sys(NR_newfstatat, AT_FDCWD, old, &st, AT_SYMLINK_NOFOLLOW);
    if (r < 0) return r;
    if ((st.mode & S_IFMT) == S_IFDIR) return -EPERM;
    if ((st.mode & S_IFMT) == S_IFLNK && resolve_link(old, intermediate, final)) {
        with_count(final, count_of(final) + 1, next);
        if ((r = sys(NR_renameat, AT_FDCWD, final, AT_FDCWD, next)) < 0) return r;
        sys(NR_unlinkat, AT_FDCWD, intermediate, 0, 0);
        if ((r = sys(NR_symlinkat, next, AT_FDCWD, intermediate, 0)) < 0) return r;
    } else {
        const char* name = base_name(old);
        long dir = name - old;
        long n = dir + (long) sizeof(PREFIX) - 1 + length_of(name);
        if (n + 10 >= PATH_MAX) return -ENAMETOOLONG;
        memcpy(intermediate, old, dir);
        memcpy(intermediate + dir, PREFIX, sizeof(PREFIX) - 1);
        memcpy(intermediate + dir + sizeof(PREFIX) - 1, name, length_of(name));
        /* The first free suffix; a dangling intermediate counts as free. */
        for (long suffix = 1;; suffix++) {
            if (suffix == 1000) return -EPERM;
            memcpy(intermediate + n, "0000", 5);
            with_count(intermediate, suffix, intermediate);
            if (sys(NR_faccessat, AT_FDCWD, intermediate, 0, 0) == -ENOENT) break;
        }
        memcpy(final, intermediate, n + 4);
        memcpy(final + n + 4, ".0002", 6);
        if ((r = sys(NR_renameat, AT_FDCWD, old, AT_FDCWD, final)) < 0) return r;
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
