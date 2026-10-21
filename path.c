/*
 * Guest paths to host paths and back.
 *
 * A guest path is resolved as the kernel would resolve it if the rootfs were
 * "/": one component at a time, symlink contents read as guest paths, ".."
 * stopping at the root. A binding maps a guest directory (or file) to a host
 * one; once the path enters a binding with no other binding below it, the
 * kernel resolves the rest on the host side (/proc's magic links need that).
 * Most paths have no symlink at all: one openat2(RESOLVE_NO_SYMLINKS) proves
 * it, and the walk is skipped.
 */

#include "burrow.h"

/* The binding holding the resolved guest path @p (@n bytes), if any. */
static const struct bind* binding_of(const char* p, long n) {
    const struct bind* best = 0;
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        long g = b->guest_length;
        if (g <= n && memcmp(p, b->guest, g) == 0 && (p[g] == 0 || p[g] == '/') &&
            (best == 0 || g > best->guest_length))
            best = b;
    }
    return best;
}

/* Whether a binding lies strictly below the guest directory @p (@n bytes). */
static int binds_below(const char* p, long n) {
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        if (b->guest_length > n && memcmp(b->guest, p, n) == 0 && b->guest[n] == '/') return 1;
    }
    return 0;
}

/* Joins @a (@an bytes) and the string @b into @to. */
static long join(char* to, const char* a, long an, const char* b) {
    long bn = length_of(b);
    if (an + bn >= PATH_MAX) return -ENAMETOOLONG;
    memmove(to, a, an);
    memmove(to + an, b, bn + 1);
    return an + bn;
}

/* The host path of the resolved guest path @p (@n bytes), as the kernel would
 * find it without symlinks. */
static long host_of(const char* p, long n, char* host) {
    const struct bind* b = binding_of(p, n);
    if (b != 0) return join(host, b->host, b->host_length, p + b->guest_length);
    return join(host, cfg.root, cfg.root_length, n == 1 ? "" : p);
}

/* Whether the host path @s starts with the directory @prefix (@n bytes). */
static int under(const char* s, const char* prefix, long n) {
    return n > 0 && memcmp(s, prefix, n) == 0 && (s[n] == 0 || s[n] == '/');
}

long host_to_guest(const char* host, char* out, long size) {
    const char* rest = 0;
    const char* guest = "";
    long best = 0;
    if (under(host, cfg.root, cfg.root_length)) best = cfg.root_length, rest = host + best;
    if (cfg.root_alias_length > best && under(host, cfg.root_alias, cfg.root_alias_length))
        best = cfg.root_alias_length, rest = host + best;
    for (int i = 0; i < cfg.bind_count; i++) {
        const struct bind* b = &cfg.binds[i];
        if (b->host_length > best && under(host, b->host, b->host_length))
            best = b->host_length, rest = host + best, guest = b->guest;
    }
    if (rest == 0) return copy(out, size, host);
    long g = length_of(guest), r = length_of(rest);
    if (g == 0 && r == 0) return copy(out, size, "/");
    if (g + r >= size) return -ENAMETOOLONG;
    memmove(out, guest, g); /* guest is never out */
    memmove(out + g, rest, r + 1);
    return g + r;
}

/* Symlink content naming a host path in the rootfs (link2symlink's links)
 * becomes the guest path, in place. */
static long unhost(char* t, long n) {
    const char* roots[] = {cfg.root, cfg.root_alias};
    long lengths[] = {cfg.root_length, cfg.root_alias_length};
    for (int i = 0; i < 2; i++) {
        long l = lengths[i];
        if (l > 0 && n >= l && memcmp(t, roots[i], l) == 0 && (n == l || t[l] == '/')) {
            if (n == l) {
                t[0] = '/';
                t[1] = 0;
                return 1;
            }
            memmove(t, t + l, n - l + 1);
            return n - l;
        }
    }
    return n;
}

long guest_absolute(long dirfd, const char* path, char* out) {
    if (path[0] == '/') {
        long r = copy(out, PATH_MAX, path);
        return r < 0 ? r : 0;
    }
    char host[PATH_MAX];
    long r;
    if (dirfd == AT_FDCWD) {
        r = sys(NR_getcwd, host, PATH_MAX, 0, 0);
        if (r < 0) return r;
    } else {
        char link[32] = "/proc/self/fd/";
        if ((int) dirfd < 0) return -EBADF;
        format_unsigned(link + 14, (unsigned long) (int) dirfd);
        r = sys(NR_readlinkat, AT_FDCWD, link, host, PATH_MAX - 1);
        if (r < 0) return -EBADF;
        host[r] = 0;
        if (host[0] != '/') return -ENOTDIR; /* a pipe, a socket... */
    }
    long n = host_to_guest(host, out, PATH_MAX);
    if (n < 0) return n;
    if (n > 1) out[n++] = '/';
    r = join(out, out, n, path);
    return r < 0 ? r : 0;
}

/* Whether the absolute guest path @p has no empty, "." or ".." component and
 * no trailing slash: the kernel resolves it as we would, symlinks apart. */
static int plain(const char* p) {
    if (p[0] != '/') return 0;
    if (p[1] == 0) return 1;
    for (long i = 1;; i++) {
        long start = i;
        while (p[i] != 0 && p[i] != '/') i++;
        long n = i - start;
        if (n == 0 || (n == 1 && p[start] == '.') || (n == 2 && p[start] == '.' && p[start + 1] == '.')) return 0;
        if (p[i] == 0) return 1;
    }
}

/* Whether the host path @host exists without any symlink (the last component
 * is not followed unless @follow). */
static long no_symlinks(const char* host, int follow, long extra) {
    struct open_how how = {O_PATH | O_CLOEXEC | (follow ? 0 : O_NOFOLLOW) | extra, 0, RESOLVE_NO_SYMLINKS};
    long fd = sys(NR_openat2, AT_FDCWD, host, &how, sizeof(how));
    if (fd >= 0) sys(NR_close, fd, 0, 0, 0);
    return fd < 0 ? fd : 0;
}

/* The slow path: resolves @path one component at a time. */
static long walk(const char* path, int follow, char* host, char* out) {
    char rest[PATH_MAX], target[PATH_MAX];
    long rest_length = copy(rest, PATH_MAX, path);
    if (rest_length < 0) return rest_length;
    int slash = rest_length > 1 && rest[rest_length - 1] == '/'; /* the last component must be a directory */
    if (slash) follow = 1;
    long n = 1, at = 0, links = 0;
    out[0] = '/';
    out[1] = 0;
    for (;;) {
        while (rest[at] == '/') at++;
        if (rest[at] == 0) break;
        long start = at;
        while (rest[at] != 0 && rest[at] != '/') at++;
        long length = at - start;
        const char* c = rest + start;
        if (length == 1 && c[0] == '.') continue;
        if (length == 2 && c[0] == '.' && c[1] == '.') {
            while (n > 1 && out[n - 1] != '/') n--;
            if (n > 1) n--;
            out[n] = 0;
            continue;
        }
        if (n + 1 + length >= PATH_MAX) return -ENAMETOOLONG;
        long previous = n;
        if (n > 1) out[n++] = '/';
        memcpy(out + n, c, length);
        n += length;
        out[n] = 0;
        long after = at;
        while (rest[after] == '/') after++;
        int last = rest[after] == 0;

        const struct bind* b = binding_of(out, n);
        if (b != 0 && !binds_below(out, n)) {
            /* The host resolves the rest: /proc's magic links, /dev's... */
            long h = join(host, b->host, b->host_length, out + b->guest_length);
            if (h < 0) return h;
            h = join(host, host, h, rest + at);
            if (h < 0) return h;
            return join(out, out, n, rest + at) < 0 ? -ENAMETOOLONG : 0;
        }
        if (last && !follow) break;

        struct kstat st;
        long r = host_of(out, n, host);
        if (r < 0) return r;
        r = sys(NR_newfstatat, AT_FDCWD, host, &st, AT_SYMLINK_NOFOLLOW);
        if (r == -ENOENT && last) break; /* to be created */
        if (r < 0) return r;
        if ((st.mode & S_IFMT) == S_IFLNK) {
            if (++links > 40) return -ELOOP;
            long t = sys(NR_readlinkat, AT_FDCWD, host, target, PATH_MAX - 1);
            if (t < 0) return t;
            target[t] = 0;
            t = unhost(target, t);
            long tail = rest_length - at;
            if (t + tail >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(target + t, rest + at, tail + 1);
            rest_length = t + tail;
            memcpy(rest, target, rest_length + 1);
            at = 0;
            n = target[0] == '/' ? 1 : previous;
            out[n] = 0;
            continue;
        }
        if (!last && (st.mode & S_IFMT) != S_IFDIR) return -ENOTDIR;
        if (last) break;
    }
    long h = host_of(out, n, host);
    if (h < 0) return h;
    if (slash && n > 1) {
        if (h + 1 >= PATH_MAX) return -ENAMETOOLONG;
        host[h] = '/';
        host[h + 1] = 0;
    }
    return 0;
}

static int is_self_exe(const char* p) {
    return same(p, "/proc/self/exe") || same(p, "/proc/thread-self/exe");
}

long to_host(const char* guest, int follow, char* host, char* resolved) {
    char scratch[PATH_MAX];
    if (resolved == 0) resolved = scratch;
    if (is_self_exe(guest) && follow) {
        long r = copy(host, PATH_MAX, cfg.host_exe);
        if (r >= 0) r = copy(resolved, PATH_MAX, cfg.exe);
        return r < 0 ? r : 0;
    }
    long n = length_of(guest);
    if (plain(guest) && binding_of(guest, n) == 0) {
        long h = host_of(guest, n, host);
        if (h < 0) return h;
        long r = no_symlinks(host, follow, 0);
        if (r == -ENOENT) {
            /* Missing: fine if its directory has no symlink (a file to create). */
            long slash = h;
            while (host[slash] != '/') slash--;
            if (slash <= cfg.root_length) {
                r = 0;
            } else {
                host[slash] = 0;
                r = no_symlinks(host, 1, O_DIRECTORY);
                host[slash] = '/';
            }
        }
        /* ENOENT, ENOTDIR: met before any symlink, so the walk would too. */
        if (r == 0 || r == -ENOENT || r == -ENOTDIR || r == -EACCES) {
            if (r == 0) memcpy(resolved, guest, n + 1);
            return r;
        }
        /* ELOOP: a symlink on the way. */
    }
    return walk(guest, follow, host, resolved);
}

long host_path(long dirfd, const char* path, int follow, char* host) {
    char guest[PATH_MAX];
    if (path == 0) return -EFAULT;
    if (path[0] == 0) return -ENOENT;
    long r = guest_absolute(dirfd, path, guest);
    return r < 0 ? r : to_host(guest, follow, host, 0);
}
