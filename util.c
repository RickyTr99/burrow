/* What Burrow needs of a C library: it has none, being freestanding. */

#include "burrow.h"

/* The compiler may emit calls to these. */
void* memcpy(void* to, const void* from, size_t n) {
    char* t = to;
    const char* f = from;
    while (n--) *t++ = *f++;
    return to;
}

void* memmove(void* to, const void* from, size_t n) {
    char* t = to;
    const char* f = from;
    if (t < f) {
        while (n--) *t++ = *f++;
    } else {
        while (n--) t[n] = f[n];
    }
    return to;
}

void* memset(void* to, int c, size_t n) {
    char* t = to;
    while (n--) *t++ = (char) c;
    return to;
}

int memcmp(const void* a, const void* b, size_t n) {
    const unsigned char* x = a;
    const unsigned char* y = b;
    for (size_t i = 0; i < n; i++)
        if (x[i] != y[i]) return x[i] - y[i];
    return 0;
}

long length_of(const char* s) {
    long n = 0;
    while (s[n]) n++;
    return n;
}

int same(const char* a, const char* b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

int starts_with(const char* s, const char* prefix) {
    while (*prefix)
        if (*s++ != *prefix++) return 0;
    return 1;
}

long copy(char* to, long size, const char* from) {
    long n = length_of(from);
    if (n >= size) return -ENAMETOOLONG;
    memcpy(to, from, n + 1);
    return n;
}

char* format_unsigned(char* to, unsigned long value) {
    char digits[24];
    int n = 0;
    do digits[n++] = (char) ('0' + value % 10);
    while ((value /= 10) != 0);
    while (n > 0) *to++ = digits[--n];
    *to = 0;
    return to;
}

unsigned long parse_unsigned(const char** s) {
    unsigned long value = 0;
    while (**s >= '0' && **s <= '9') value = value * 10 + (unsigned long) (*(*s)++ - '0');
    return value;
}

void say(const char* a, const char* b, const char* c) {
    const char* parts[] = {"burrow: ", a, b, c, "\n"};
    for (unsigned i = 0; i < sizeof(parts) / sizeof(*parts); i++)
        if (parts[i]) sys(NR_write, 2, parts[i], length_of(parts[i]), 0);
}

void die(const char* a, const char* b) {
    say(a, b, 0);
    sys(NR_exit_group, 127, 0, 0, 0);
    __builtin_unreachable();
}
