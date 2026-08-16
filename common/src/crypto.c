#include "tunnelmate/crypto.h"
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

tm_status tm_rand_bytes(uint8_t *out, size_t len) {
    if (RAND_bytes(out, (int)len) != 1) return TM_ERR;
    return TM_OK;
}

static const char alphabet[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

char *tm_rand_token(char *buf, size_t len) {
    if (len == 0) { buf[0] = 0; return buf; }
    uint8_t *raw = tm_xmalloc(len);
    if (tm_rand_bytes(raw, len) != TM_OK) {
        free(raw);
        buf[0] = 0;
        return buf;
    }
    for (size_t i = 0; i < len; i++) buf[i] = alphabet[raw[i] % (sizeof(alphabet) - 1)];
    buf[len] = 0;
    free(raw);
    return buf;
}

void tm_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    unsigned int olen = 0;
    HMAC(EVP_sha256(), key, (int)key_len, msg, msg_len, out, &olen);
}

static const char hexd[] = "0123456789abcdef";

void tm_sha256_hex(const uint8_t *msg, size_t msg_len, char out[65]) {
    uint8_t digest[32];
    unsigned int olen = 0;
    EVP_Digest(msg, msg_len, digest, &olen, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hexd[digest[i] >> 4];
        out[i * 2 + 1] = hexd[digest[i] & 0xF];
    }
    out[64] = 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool tm_ct_eq_hex(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < la; i += 2) {
        int ah = hexval(a[i]), al = hexval(a[i + 1]);
        int bh = hexval(b[i]), bl = hexval(b[i + 1]);
        if (ah < 0 || al < 0 || bh < 0 || bl < 0) return false;
        diff |= (uint8_t)((ah << 4 | al) ^ (bh << 4 | bl));
    }
    return diff == 0;
}