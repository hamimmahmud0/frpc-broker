#ifndef TM_CONFIG_H
#define TM_CONFIG_H

#include "tunnelmate/common.h"

/* Minimal TOML-subset parser: [section] headers, key = value, strings,
   integers, booleans, floats, arrays of strings/ints, # comments. */

typedef struct tm_config tm_config;

tm_config *tm_config_new(void);
void tm_config_free(tm_config *c);

/* Parse file; returns TM_OK or TM_ERR (errbuf filled). */
tm_status tm_config_load(tm_config *c, const char *path,
                         char *errbuf, size_t errlen);
/* Parse from memory (used by tests). */
tm_status tm_config_parse(tm_config *c, const char *text,
                          char *errbuf, size_t errlen);

/* Lookups. Keys may be "section.key" or plain "key". */
bool tm_config_get_str(const tm_config *c, const char *key,
                       const char *def, const char **out);
bool tm_config_get_int(const tm_config *c, const char *key, long long def,
                       long long *out);
bool tm_config_get_bool(const tm_config *c, const char *key, bool def,
                        bool *out);
bool tm_config_get_double(const tm_config *c, const char *key, double def,
                          double *out);

const char *tm_config_get_str_owned(const tm_config *c, const char *key,
                                    const char *def);

#endif