#include "tunnelmate/log.h"
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

struct tm_logger {
    int fd;
    char component[32];
    tm_log_level level;
};

tm_logger *tm_log_new(int fd, const char *component, tm_log_level level) {
    tm_logger *lg = calloc(1, sizeof(*lg));
    if (!lg) return NULL;
    lg->fd = fd;
    lg->level = level;
    snprintf(lg->component, sizeof(lg->component), "%s", component);
    return lg;
}

void tm_log_free(tm_logger *lg) { free(lg); }

const char *tm_log_level_name(tm_log_level lvl) {
    switch (lvl) {
    case TM_LOG_DEBUG: return "debug";
    case TM_LOG_INFO:  return "info";
    case TM_LOG_WARN:  return "warning";
    case TM_LOG_ERROR: return "error";
    default: return "info";
    }
}

int tm_log_level_parse(const char *s, tm_log_level *out) {
    if (!s) return -1;
    if (!strcmp(s, "debug")) { *out = TM_LOG_DEBUG; return 0; }
    if (!strcmp(s, "info")) { *out = TM_LOG_INFO; return 0; }
    if (!strcmp(s, "warn") || !strcmp(s, "warning")) { *out = TM_LOG_WARN; return 0; }
    if (!strcmp(s, "error")) { *out = TM_LOG_ERROR; return 0; }
    return -1;
}

/* JSON-stringify `s` into out (max outlen); returns bytes written. */
static size_t json_escape(const char *s, char *out, size_t outlen) {
    size_t n = 0;
    for (const char *p = s; *p && n + 6 < outlen; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"': out[n++] = '\\'; out[n++] = '"'; break;
        case '\\': out[n++] = '\\'; out[n++] = '\\'; break;
        case '\n': out[n++] = '\\'; out[n++] = 'n'; break;
        case '\r': out[n++] = '\\'; out[n++] = 'r'; break;
        case '\t': out[n++] = '\\'; out[n++] = 't'; break;
        default:
            if (c < 0x20) {
                out[n++] = '\\'; out[n++] = 'u';
                snprintf(out + n, outlen - n, "%04x", c);
                n += 4;
            } else out[n++] = (char)c;
        }
    }
    out[n] = 0;
    return n;
}

static void write_log(tm_logger *lg, const char *line) {
    ssize_t len = (ssize_t)strlen(line);
    size_t off = 0;
    while (off < (size_t)len) {
        ssize_t w = write(lg->fd, line + off, (size_t)(len - (ssize_t)off));
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += (size_t)w;
    }
}

void tm_log_event(tm_logger *lg, tm_log_level lvl, const char *event,
                  const char *key, const char *value, ...) {
    if (!lg || lvl < lg->level) return;
    char ts[64];
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    struct tm tmv;
    localtime_r(&tv.tv_sec, &tmv);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tmv);
    char line[1024];
    size_t n = 0;
    n += (size_t)snprintf(line + n, sizeof(line) - n,
        "{\"ts\":\"%s.%03ld\",\"level\":\"%s\",\"component\":\"%s\",\"event\":\"%s\"",
        ts, tv.tv_nsec / 1000000L, tm_log_level_name(lvl), lg->component, event);
    va_list ap;
    va_start(ap, value);
    const char *fmt = va_arg(ap, const char *);
    char vbuf[512];
    if (fmt)
        vsnprintf(vbuf, sizeof(vbuf), fmt, ap);
    else
        vbuf[0] = 0;
    va_end(ap);
    if (key && value) {
        char ke[64], ve[768];
        json_escape(key, ke, sizeof(ke));
        json_escape(value, ve, sizeof(ve));
        n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"%s\":\"%s\"", ke, ve);
    }
    {
        char me[768];
        json_escape(vbuf, me, sizeof(me));
        n += (size_t)snprintf(line + n, sizeof(line) - n, ",\"message\":\"%s\"", me);
    }
    snprintf(line + n, sizeof(line) - n, "}\n");
    write_log(lg, line);
}

void tm_log_msg(tm_logger *lg, tm_log_level lvl, const char *fmt, ...) {
    if (!lg || lvl < lg->level) return;
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    write_log(lg, line);
}