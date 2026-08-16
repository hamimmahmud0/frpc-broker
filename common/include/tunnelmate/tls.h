#ifndef TM_TLS_H
#define TM_TLS_H

#include "tunnelmate/common.h"
#include <openssl/ssl.h>
#include <uv.h>

/* SSL stream wrapper for libuv. Uses memory BIOs; ciphertext is shipped via
   uv_write, whose completion acts as the socket-writability notification.
   Supports TLS 1.2/1.3 and DTLS 1.3. */

typedef struct tm_ssl_stream tm_ssl_stream;

typedef void (*tm_ssl_handshake_cb)(tm_ssl_stream *s, int ok, void *arg);
typedef void (*tm_ssl_read_cb)(tm_ssl_stream *s, const uint8_t *data,
                               size_t len, void *arg);
typedef void (*tm_ssl_eof_cb)(tm_ssl_stream *s, void *arg);
typedef void (*tm_ssl_error_cb)(tm_ssl_stream *s, int err, void *arg);

typedef struct {
    tm_ssl_handshake_cb handshake_cb;
    tm_ssl_read_cb read_cb;
    tm_ssl_eof_cb eof_cb;
    tm_ssl_error_cb error_cb;
    void *arg;
} tm_ssl_cbs;

/* Server contexts */
SSL_CTX *tm_tls_server_ctx(const char *cert_path, const char *key_path,
                           char *errbuf, size_t errlen);
SSL_CTX *tm_dtls_server_ctx(const char *cert_path, const char *key_path,
                            char *errbuf, size_t errlen);

/* Client contexts. verify=0 disables certificate verification (development
   only, must be explicitly configured); hostname checked when verify=1. */
SSL_CTX *tm_tls_client_ctx(const char *ca_path, bool verify,
                           char *errbuf, size_t errlen);
SSL_CTX *tm_dtls_client_ctx(const char *ca_path, bool verify,
                            char *errbuf, size_t errlen);

/* Configure SNI and certificate hostname/IP verification on a client SSL.
   Call once after SSL_new and before the handshake. */
tm_status tm_tls_configure_client_ssl(SSL *ssl, const char *hostname,
                                      bool verify);

tm_status tm_dtls_attach_bio_pair(SSL *ssl, BIO **rbio, BIO **wbio);

/* SSL* objects. tls_type: 1 = TLS, 0 = DTLS. */
SSL *tm_ssl_new(SSL_CTX *ctx, bool is_dtls);

/* Attach to a connected uv TCP stream. Ownership of socket stays with caller;
   caller must close it after tm_ssl_stream_close. */
tm_ssl_stream *tm_ssl_stream_new(uv_loop_t *loop, uv_stream_t *socket,
                                 SSL *ssl, bool is_server, const tm_ssl_cbs *cbs);

/* For DTLS: attach to a uv_udp handle; peer is the connected remote. */
tm_ssl_stream *tm_dtls_stream_new(uv_loop_t *loop, uv_udp_t *udp, SSL *ssl,
                                  bool is_server, const tm_ssl_cbs *cbs);

void tm_ssl_stream_start(tm_ssl_stream *s);
/* Half-close: send close_notify. */
void tm_ssl_stream_shutdown_send(tm_ssl_stream *s);
/* Queue plaintext for encryption and transmission. Returns TM_OK or
   TM_ERR_BUSY (caller must not queue unbounded data; use high watermark). */
tm_status tm_ssl_stream_write(tm_ssl_stream *s, const uint8_t *data, size_t len);
size_t tm_ssl_stream_pending(tm_ssl_stream *s);
uint64_t tm_ssl_stream_write_total(tm_ssl_stream *s);
bool tm_ssl_stream_drained(tm_ssl_stream *s);
/* Close and free; free_cb invoked with the user arg afterwards. */
void tm_ssl_stream_close(tm_ssl_stream *s);

/* Bounded internal plaintext write queue: returns false when the queue is at
   its high watermark (relay must stop reading the source). */
bool tm_ssl_stream_write_available(tm_ssl_stream *s);

/* Initiate a TLS/DTLS connect (client) or accept (server) handshake. */
void tm_ssl_stream_handshake(tm_ssl_stream *s);

bool tm_ssl_is_dtls(tm_ssl_stream *s);

/* backpressure plumbing */
typedef void (*tm_ssl_low_cb)(tm_ssl_stream *s, void *arg);
void tm_ssl_stream_set_low_cb(tm_ssl_stream *s, tm_ssl_low_cb cb, void *arg);
void tm_ssl_stream_pause_read(tm_ssl_stream *s);
void tm_ssl_stream_resume_read(tm_ssl_stream *s);

#endif
