#include "tunnelmate/common.h"
#include <time.h>
#include <errno.h>

bool tm_utf8_valid(const uint8_t *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t c = s[i];
        if (c < 0x80) { i++; continue; }
        int cont;
        uint32_t cp;
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; cont = 1; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; cont = 2; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; cont = 3; }
        else return false;
        if (i + (size_t)cont >= len + 1) { return false; }
        if (i + (size_t)cont > len) return false;
        for (int j = 1; j <= cont; j++) {
            if ((s[i + j] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (s[i + j] & 0x3F);
        }
        /* overlong / surrogate / out-of-range */
        if ((cont == 1 && cp < 0x80) || (cont == 2 && cp < 0x800) ||
            (cont == 3 && cp < 0x10000) || cp > 0x10FFFF ||
            (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += (size_t)cont + 1;
    }
    return true;
}

bool tm_ct_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

void *tm_xcalloc(size_t n, size_t sz) {
    void *p = calloc(n, sz);
    if (!p) { fprintf(stderr, "out of memory\n"); abort(); }
    return p;
}

void *tm_xmalloc(size_t sz) {
    void *p = malloc(sz ? sz : 1);
    if (!p) { fprintf(stderr, "out of memory\n"); abort(); }
    return p;
}

char *tm_xstrdup(const char *s) {
    char *p = strdup(s);
    if (!p) { fprintf(stderr, "out of memory\n"); abort(); }
    return p;
}

void *tm_xrealloc(void *p, size_t sz) {
    void *q = realloc(p, sz ? sz : 1);
    if (!q) { fprintf(stderr, "out of memory\n"); abort(); }
    return q;
}

uint64_t tm_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000u);
}