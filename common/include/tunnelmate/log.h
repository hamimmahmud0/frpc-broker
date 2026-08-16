#ifndef TM_LOG_H
#define TM_LOG_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    TM_LOG_DEBUG = 0,
    TM_LOG_INFO = 1,
    TM_LOG_WARN = 2,
    TM_LOG_ERROR = 3
} tm_log_level;

typedef struct tm_logger tm_logger;

/* Create a logger writing to fd (stderr or file). Never logs payloads. */
tm_logger *tm_log_new(int fd, const char *component, tm_log_level level);
void tm_log_free(tm_logger *lg);

/* A key-value event. `key` must be a static string literal or otherwise
   outlive the call. Structured output:
   {"ts":"...","level":"info","component":"broker","event":"accept","k":"v"} */
/* key/value is an optional literal pair (both or neither); the first
   variadic argument is a printf-style message format. */
void tm_log_event(tm_logger *lg, tm_log_level lvl, const char *event,
                  const char *key, const char *value, ...);

void tm_log_msg(tm_logger *lg, tm_log_level lvl, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define tm_log_debug(lg, ev, ...) tm_log_event((lg), TM_LOG_DEBUG, (ev), NULL, NULL, __VA_ARGS__)
#define tm_log_info(lg, ev, ...)  tm_log_event((lg), TM_LOG_INFO, (ev), NULL, NULL, __VA_ARGS__)
#define tm_log_warn(lg, ev, ...)  tm_log_event((lg), TM_LOG_WARN, (ev), NULL, NULL, __VA_ARGS__)
#define tm_log_error(lg, ev, ...) tm_log_event((lg), TM_LOG_ERROR, (ev), NULL, NULL, __VA_ARGS__)

const char *tm_log_level_name(tm_log_level lvl);
int tm_log_level_parse(const char *s, tm_log_level *out);

#endif