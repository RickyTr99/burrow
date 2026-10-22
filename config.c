/*
 * Burrow's state, carried across execve() in the BURROW environment variable:
 * fields separated by 0x1f, numbers in decimal.
 */

#include "burrow.h"

struct config cfg;

#define SEP '\x1f'

/* Android shows the app's data directory both as /data/user/0/<package> and
 * as /data/data/<package>; proot wrote the latter into link2symlink's links. */
void set_root_alias(void) {
    static const char* const pairs[][2] = {{"/data/user/0/", "/data/data/"}, {"/data/data/", "/data/user/0/"}};
    cfg.root_alias_length = 0;
    cfg.root_alias[0] = 0;
    for (unsigned i = 0; i < 2; i++) {
        if (!starts_with(cfg.root, pairs[i][0])) continue;
        long head = length_of(pairs[i][1]);
        long tail = cfg.root_length - length_of(pairs[i][0]);
        if (head + tail >= (long) sizeof(cfg.root_alias)) return;
        memcpy(cfg.root_alias, pairs[i][1], head);
        memcpy(cfg.root_alias + head, cfg.root + length_of(pairs[i][0]), tail + 1);
        cfg.root_alias_length = head + tail;
        return;
    }
}

static char* put(char* at, char* end, const char* s) {
    long n = length_of(s);
    if (at == 0 || at + n + 1 >= end) return 0;
    memcpy(at, s, n);
    at[n] = SEP;
    return at + n + 1;
}

static char* put_number(char* at, char* end, unsigned long value) {
    char digits[24];
    format_unsigned(digits, value);
    return put(at, end, digits);
}

long encode_config(char* to, long size, const char* exe, const char* host_exe, const char* name) {
    char* end = to + size;
    char* at = put(to, end, "3");
    at = put(at, end, cfg.root);
    at = put(at, end, cfg.self);
    at = put_number(at, end, cfg.real_uid);
    at = put_number(at, end, cfg.real_gid);
    for (int i = 0; i < ID_COUNT; i++) at = put_number(at, end, __atomic_load_n(&cfg.ids[i], __ATOMIC_RELAXED));
    at = put(at, end, exe);
    at = put(at, end, host_exe);
    at = put(at, end, name);
    at = put_number(at, end, cfg.dns_port);
    at = put_number(at, end, (unsigned long) cfg.group_count);
    for (int i = 0; i < cfg.group_count; i++) at = put_number(at, end, cfg.groups[i]);
    at = put_number(at, end, (unsigned long) cfg.bind_count);
    for (int i = 0; i < cfg.bind_count; i++) {
        at = put(at, end, cfg.binds[i].guest);
        at = put(at, end, cfg.binds[i].host);
    }
    if (at == 0) return -E2BIG;
    at[-1] = 0;
    return at - 1 - to;
}

/* Copies the field at *@s into @to and moves past it. */
static int take(const char** s, char* to, long size) {
    long n = 0;
    while ((*s)[n] && (*s)[n] != SEP) n++;
    if (n >= size) return 0;
    memcpy(to, *s, n);
    to[n] = 0;
    *s += n + ((*s)[n] == SEP);
    return 1;
}

static int take_number(const char** s, unsigned long* value) {
    char digits[24];
    if (!take(s, digits, sizeof(digits))) return 0;
    const char* d = digits;
    *value = parse_unsigned(&d);
    return *d == 0 && d != digits;
}

int decode_config(const char* s) {
    char version[8];
    unsigned long v;
    if (!take(&s, version, sizeof(version)) || !same(version, "3")) return 0;
    if (!take(&s, cfg.root, sizeof(cfg.root)) || !take(&s, cfg.self, sizeof(cfg.self))) return 0;
    if (!take_number(&s, &v)) return 0;
    cfg.real_uid = (uint32_t) v;
    if (!take_number(&s, &v)) return 0;
    cfg.real_gid = (uint32_t) v;
    for (int i = 0; i < ID_COUNT; i++) {
        if (!take_number(&s, &v)) return 0;
        cfg.ids[i] = (uint32_t) v;
    }
    if (!take(&s, cfg.exe, sizeof(cfg.exe)) || !take(&s, cfg.host_exe, sizeof(cfg.host_exe)) ||
        !take(&s, cfg.name, sizeof(cfg.name)))
        return 0;
    if (!take_number(&s, &v) || v > 65535) return 0;
    cfg.dns_port = (uint16_t) v;
    if (!take_number(&s, &v) || v > MAX_GROUPS) return 0;
    cfg.group_count = (int) v;
    for (int i = 0; i < cfg.group_count; i++) {
        if (!take_number(&s, &v)) return 0;
        cfg.groups[i] = (uint32_t) v;
    }
    if (!take_number(&s, &v) || v > MAX_BINDS) return 0;
    cfg.bind_count = (int) v;
    for (int i = 0; i < cfg.bind_count; i++) {
        struct bind* b = &cfg.binds[i];
        if (!take(&s, b->guest, sizeof(b->guest)) || !take(&s, b->host, sizeof(b->host))) return 0;
        b->guest_length = length_of(b->guest);
        b->host_length = length_of(b->host);
    }
    cfg.root_length = length_of(cfg.root);
    set_root_alias();
    return 1;
}
