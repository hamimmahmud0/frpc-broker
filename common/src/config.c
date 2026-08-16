#include "tunnelmate/config.h"

typedef struct tm_kv {
    char *key;
    char *value;
    struct tm_kv *next;
} tm_kv;

struct tm_config {
    tm_kv *head;
};

tm_config *tm_config_new(void) { return tm_xcalloc(1, sizeof(tm_config)); }

void tm_config_free(tm_config *c) {
    if (!c) return;
    tm_kv *k = c->head;
    while (k) {
        tm_kv *n = k->next;
        free(k->key);
        free(k->value);
        free(k);
        k = n;
    }
    free(c);
}

static void config_set(tm_config *c, const char *section, const char *key,
                       const char *value) {
    char full[256];
    if (section && section[0])
        snprintf(full, sizeof(full), "%s.%s", section, key);
    else
        snprintf(full, sizeof(full), "%s", key);
    /* replace existing */
    for (tm_kv *k = c->head; k; k = k->next) {
        if (!strcmp(k->key, full)) {
            free(k->value);
            k->value = tm_xstrdup(value);
            return;
        }
    }
    tm_kv *k = tm_xcalloc(1, sizeof(*k));
    k->key = tm_xstrdup(full);
    k->value = tm_xstrdup(value);
    k->next = c->head;
    c->head = k;
}

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) s[--n] = 0;
}

static int parse_line(tm_config *c, char *line, const char *section,
                      char *errbuf, size_t errlen, int lineno) {
    char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (*p == 0 || *p == '#') return 0;
    if (*p == '[') {
        char *end = strchr(p, ']');
        if (!end) {
            snprintf(errbuf, errlen, "line %d: unterminated section", lineno);
            return -1;
        }
        *end = 0;
        return 0; /* caller handles section via out param */
    }
    char *eq = strchr(p, '=');
    if (!eq) {
        snprintf(errbuf, errlen, "line %d: expected '='", lineno);
        return -1;
    }
    *eq = 0;
    trim(p);
    char *v = eq + 1;
    trim(v);
    /* strip quotes */
    size_t vl = strlen(v);
    if (vl >= 2 && ((v[0] == '"' && v[vl - 1] == '"') ||
                    (v[0] == '\'' && v[vl - 1] == '\''))) {
        v[vl - 1] = 0;
        v++;
    }
    if (!p[0]) {
        snprintf(errbuf, errlen, "line %d: empty key", lineno);
        return -1;
    }
    config_set(c, section, p, v);
    return 0;
}

static tm_status config_parse_buf(tm_config *c, const char *text,
                                  char *errbuf, size_t errlen) {
    char *copy = tm_xstrdup(text);
    char *section = NULL;
    char *save = NULL;
    int lineno = 0;
    for (char *line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '[') {
            char *end = strchr(p, ']');
            if (!end) {
                snprintf(errbuf, errlen, "line %d: unterminated section", lineno);
                free(section);
                free(copy);
                return TM_ERR;
            }
            *end = 0;
            free(section);
            section = tm_xstrdup(p + 1);
            continue;
        }
        if (parse_line(c, line, section, errbuf, errlen, lineno) != 0) {
            free(section);
            free(copy);
            return TM_ERR;
        }
    }
    free(section);
    free(copy);
    return TM_OK;
}

tm_status tm_config_parse(tm_config *c, const char *text,
                          char *errbuf, size_t errlen) {
    return config_parse_buf(c, text, errbuf, errlen);
}

tm_status tm_config_load(tm_config *c, const char *path,
                         char *errbuf, size_t errlen) {
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(errbuf, errlen, "cannot open config '%s'", path);
        return TM_ERR;
    }
    char *buf = NULL;
    size_t cap = 0, len = 0;
    char chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) {
        if (len + n + 1 > cap) {
            cap = cap ? cap * 2 : 8192;
            while (cap < len + n + 1) cap *= 2;
            buf = tm_xrealloc(buf, cap);
        }
        memcpy(buf + len, chunk, n);
        len += n;
    }
    fclose(f);
    if (!buf) { buf = tm_xmalloc(1); buf[0] = 0; }
    buf[len] = 0;
    tm_status st = config_parse_buf(c, buf, errbuf, errlen);
    free(buf);
    return st;
}

static const char *config_find(const tm_config *c, const char *key) {
    for (const tm_kv *k = c->head; k; k = k->next) {
        if (!strcmp(k->key, key)) return k->value;
    }
    return NULL;
}

bool tm_config_get_str(const tm_config *c, const char *key,
                       const char *def, const char **out) {
    const char *v = config_find(c, key);
    if (!v) { *out = def; return false; }
    *out = v;
    return true;
}

const char *tm_config_get_str_owned(const tm_config *c, const char *key,
                                    const char *def) {
    const char *v = config_find(c, key);
    return v ? v : def;
}

bool tm_config_get_int(const tm_config *c, const char *key, long long def,
                       long long *out) {
    const char *v = config_find(c, key);
    if (!v) { *out = def; return false; }
    char *end = NULL;
    long long n = strtoll(v, &end, 10);
    if (end == v || *end) { *out = def; return false; }
    *out = n;
    return true;
}

bool tm_config_get_bool(const tm_config *c, const char *key, bool def,
                        bool *out) {
    const char *v = config_find(c, key);
    if (!v) { *out = def; return false; }
    if (!strcmp(v, "true") || !strcmp(v, "yes") || !strcmp(v, "on") || !strcmp(v, "1")) {
        *out = true; return true;
    }
    if (!strcmp(v, "false") || !strcmp(v, "no") || !strcmp(v, "off") || !strcmp(v, "0")) {
        *out = false; return true;
    }
    *out = def;
    return false;
}

bool tm_config_get_double(const tm_config *c, const char *key, double def,
                          double *out) {
    const char *v = config_find(c, key);
    if (!v) { *out = def; return false; }
    char *end = NULL;
    double d = strtod(v, &end);
    if (end == v || *end) { *out = def; return false; }
    *out = d;
    return true;
}