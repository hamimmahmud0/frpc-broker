#ifndef TM_CRYPTO_H
#define TM_CRYPTO_H

#include "tunnelmate/common.h"

/* Cryptographically secure random bytes. Returns TM_OK. */
tm_status tm_rand_bytes(uint8_t *out, size_t len);

/* Generate a printable token of the given byte-entropy using a safe
   alphabet. buf must hold len+1 bytes; returns buf. */
char *tm_rand_token(char *buf, size_t len);

/* HMAC-SHA256 keyed digest. out must hold 32 bytes. */
void tm_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* Constant-time comparison of hex digests (ASCII). */
bool tm_ct_eq_hex(const char *a, const char *b);

/* sha256 hex of `msg` (no key). out must hold 65 bytes. */
void tm_sha256_hex(const uint8_t *msg, size_t msg_len, char out[65]);

#endif