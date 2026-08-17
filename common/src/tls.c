#include "tunnelmate/tls.h"
#include "tunnelmate/common.h"
#include "tunnelmate/crypto.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* Contexts                                                            */
/* ------------------------------------------------------------------ */

static int load_cert(SSL_CTX *ctx, const char *cert, const char *key,
                     char *errbuf, size_t errlen) {
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
        snprintf(errbuf, errlen, "cannot load certificate '%s'", cert);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        snprintf(errbuf, errlen, "cannot load private key '%s'", key);
        return -1;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        snprintf(errbuf, errlen, "private key does not match certificate");
        return -1;
    }
    return 0;
}

static void ctx_base(SSL_CTX *ctx, bool is_dtls) {
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (is_dtls) {
        SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
    } else {
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    }
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
}

SSL_CTX *tm_tls_server_ctx(const char *cert_path, const char *key_path,
                           char *errbuf, size_t errlen) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { snprintf(errbuf, errlen, "SSL_CTX_new failed"); return NULL; }
    ctx_base(ctx, false);
    if (load_cert(ctx, cert_path, key_path, errbuf, errlen)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

SSL_CTX *tm_dtls_server_ctx(const char *cert_path, const char *key_path,
                            char *errbuf, size_t errlen) {
    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    if (!ctx) { snprintf(errbuf, errlen, "SSL_CTX_new failed"); return NULL; }
    ctx_base(ctx, true);
    if (load_cert(ctx, cert_path, key_path, errbuf, errlen)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

SSL_CTX *tm_tls_client_ctx(const char *ca_path, bool verify,
                           char *errbuf, size_t errlen) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { snprintf(errbuf, errlen, "SSL_CTX_new failed"); return NULL; }
    ctx_base(ctx, false);
    if (verify) {
        if (ca_path) {
            if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
                snprintf(errbuf, errlen, "cannot load CA file '%s'", ca_path);
                SSL_CTX_free(ctx);
                return NULL;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    /* verify=0 must be explicit in config; no silent downgrade */
    return ctx;
}

SSL_CTX *tm_dtls_client_ctx(const char *ca_path, bool verify,
                            char *errbuf, size_t errlen) {
    SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());
    if (!ctx) { snprintf(errbuf, errlen, "SSL_CTX_new failed"); return NULL; }
    ctx_base(ctx, true);
    if (verify) {
        if (ca_path) {
            if (SSL_CTX_load_verify_locations(ctx, ca_path, NULL) != 1) {
                snprintf(errbuf, errlen, "cannot load CA file '%s'", ca_path);
                SSL_CTX_free(ctx);
                return NULL;
            }
        } else {
            SSL_CTX_set_default_verify_paths(ctx);
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
    return ctx;
}

tm_status tm_tls_configure_client_ssl(SSL *ssl, const char *hostname,
                                      bool verify) {
    if (!ssl || !hostname || !hostname[0]) return TM_ERR;
    unsigned char ipbuf[sizeof(struct in6_addr)];
    bool is_ip = inet_pton(AF_INET, hostname, ipbuf) == 1 ||
                 inet_pton(AF_INET6, hostname, ipbuf) == 1;
    if (!is_ip && SSL_set_tlsext_host_name(ssl, hostname) != 1) return TM_ERR_TLS;
    if (!verify) return TM_OK;
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    if (!param) return TM_ERR_TLS;
    if (is_ip) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, hostname) != 1) return TM_ERR_TLS;
    } else if (SSL_set1_host(ssl, hostname) != 1) {
        return TM_ERR_TLS;
    }
    return TM_OK;
}

tm_status tm_dtls_attach_bio_pair(SSL *ssl, BIO **rbio, BIO **wbio) {
    BIO *ssl_bio = NULL, *network_bio = NULL;
    if (!ssl || !rbio || !wbio) return TM_ERR;
    if (BIO_new_bio_dgram_pair(&ssl_bio, 0, &network_bio, 0) != 1)
        return TM_ERR_TLS;
    SSL_set0_rbio(ssl, ssl_bio);
    if (BIO_up_ref(ssl_bio) != 1) {
        BIO_free(network_bio);
        return TM_ERR_TLS;
    }
    SSL_set0_wbio(ssl, ssl_bio);
    /* A memory-backed datagram BIO has no socket from which libssl can query
       the path MTU.  Without an explicit MTU OpenSSL aborts the first DTLS
       flight with SSL_ERROR_SYSCALL before placing a useful error on the
       queue. */
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    if (DTLS_set_link_mtu(ssl, 1400) == 0) {
        BIO_free(network_bio);
        return TM_ERR_TLS;
    }
    *rbio = network_bio;
    if (BIO_up_ref(network_bio) != 1) return TM_ERR_TLS;
    *wbio = network_bio;
    return TM_OK;
}

SSL *tm_ssl_new(SSL_CTX *ctx, bool is_dtls) {
    (void)is_dtls;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    return ssl;
}

/* ------------------------------------------------------------------ */
/* tm_ssl_stream                                                       */
/* ------------------------------------------------------------------ */

#define TM_SSL_INBUF_SIZE 65536u
#define TM_SSL_WBUF_SIZE  65536u
#define TM_PQ_HIGH (256u * 1024u)
#define TM_PQ_LOW  (128u * 1024u)

enum { TM_SS_STATE_HANDSHAKE = 0, TM_SS_STATE_OPEN = 1, TM_SS_STATE_CLOSED = 2 };

typedef struct {
    uv_write_t req;      /* tcp write */
    uv_udp_send_t ureq;  /* udp send */
    uint8_t *data;
    struct tm_ssl_stream *s;
} tm_wreq;

struct tm_ssl_stream {
    uv_loop_t *loop;
    uv_stream_t *tcp;
    uv_udp_t *udp;
    uv_timer_t dtls_timer;
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
    tm_ssl_cbs cbs;
    bool is_dtls;
    bool is_server;
    int state;
    bool read_started;
    bool close_sent;
    uint64_t write_pq_total;  /* bytes accepted by tm_ssl_stream_write */
    bool shutdown_pending;
    bool inflight;
    uint8_t *pq;
    size_t pq_len, pq_cap, pq_off;
    size_t ssl_retry_len;
    uint8_t inbuf[TM_SSL_INBUF_SIZE];
    int last_err;
    char err_detail[224];
    bool above_low;
    bool read_paused;
    bool pumping_read;
    bool free_pending;
    bool freeing;
    tm_ssl_low_cb low_cb;
    void *low_arg;
};

static void pump_write(tm_ssl_stream *s);
static void pump_read(tm_ssl_stream *s);
static void tls_try_shutdown(tm_ssl_stream *s);
static void dtls_timer_cb(uv_timer_t *t);

static void finish_close(tm_ssl_stream *s) {
    if (s->state == TM_SS_STATE_CLOSED) return;
    s->state = TM_SS_STATE_CLOSED;
    if (s->cbs.error_cb) {
        tm_ssl_cbs cbs = s->cbs;
        s->cbs.read_cb = NULL;
        s->cbs.eof_cb = NULL;
        s->cbs.error_cb = NULL;
        cbs.error_cb(s, s->last_err ? s->last_err : TM_ERR_IO, cbs.arg);
    }
}

static void free_stream_memory(tm_ssl_stream *s) {
    if (s->ssl) SSL_free(s->ssl);
    if (s->is_dtls) {
        BIO_free(s->rbio);
        BIO_free(s->wbio);
    }
    free(s->pq);
    free(s);
}

static void dtls_timer_closed(uv_handle_t *h) {
    free_stream_memory((tm_ssl_stream *)h->data);
}

static void do_free(tm_ssl_stream *s) {
    if (s->freeing) return;
    s->freeing = true;
    if (s->is_dtls && s->dtls_timer.data &&
        !uv_is_closing((uv_handle_t *)&s->dtls_timer)) {
        uv_timer_stop(&s->dtls_timer);
        uv_close((uv_handle_t *)&s->dtls_timer, dtls_timer_closed);
        return;
    }
    free_stream_memory(s);
}

tm_ssl_stream *tm_ssl_stream_new(uv_loop_t *loop, uv_stream_t *socket,
                                 SSL *ssl, bool is_server, const tm_ssl_cbs *cbs) {
    tm_ssl_stream *s = tm_xcalloc(1, sizeof(*s));
    s->loop = loop;
    s->tcp = socket;
    s->ssl = ssl;
    s->cbs = *cbs;
    s->is_dtls = false;
    s->is_server = is_server;
    s->state = TM_SS_STATE_HANDSHAKE;
    s->rbio = BIO_new(BIO_s_mem());
    s->wbio = BIO_new(BIO_s_mem());
    if (!s->rbio || !s->wbio) { free(s); return NULL; }
    SSL_set_bio(ssl, s->rbio, s->wbio);
    if (is_server) SSL_set_accept_state(ssl);
    else SSL_set_connect_state(ssl);
    return s;
}

tm_ssl_stream *tm_dtls_stream_new(uv_loop_t *loop, uv_udp_t *udp, SSL *ssl,
                                  bool is_server, const tm_ssl_cbs *cbs) {
    tm_ssl_stream *s = tm_xcalloc(1, sizeof(*s));
    s->loop = loop;
    s->udp = udp;
    s->ssl = ssl;
    s->cbs = *cbs;
    s->is_dtls = true;
    s->is_server = is_server;
    s->state = TM_SS_STATE_HANDSHAKE;
    if (tm_dtls_attach_bio_pair(ssl, &s->rbio, &s->wbio) != TM_OK) {
        free(s);
        return NULL;
    }
    if (is_server) SSL_set_accept_state(ssl);
    else SSL_set_connect_state(ssl);
    uv_timer_init(loop, &s->dtls_timer);
    s->dtls_timer.data = s;
    return s;
}

bool tm_ssl_is_dtls(tm_ssl_stream *s) { return s->is_dtls; }

/* ------------------------- write path ------------------------------ */

static void on_write_done(uv_write_t *req, int status) {
    tm_wreq *wr = (tm_wreq *)req;
    tm_ssl_stream *s = wr->s;
    free(wr->data);
    free(wr);
    if (!s) return;
    s->inflight = false;
    if (s->state == TM_SS_STATE_CLOSED) {
        do_free(s);
        return;
    }
    if (status < 0 && status != UV_ECANCELED) {
        s->last_err = TM_ERR_IO;
        finish_close(s);
        return;
    }
    pump_write(s);
    if (s->shutdown_pending && s->state == TM_SS_STATE_OPEN)
        tls_try_shutdown(s);
}

/* Capture the OpenSSL reason for the most recent failure. Without this a TLS
   fault surfaces to the relay as a bare error code with no way to tell a
   protocol violation from a truncated stream. Bounded and free of user data. */
static void record_tls_error(tm_ssl_stream *s, const char *where, int ssl_err) {
    unsigned long code = ERR_peek_last_error();
    char reason[160];
    if (code)
        ERR_error_string_n(code, reason, sizeof(reason));
    else
        snprintf(reason, sizeof(reason), "no queued error");
    snprintf(s->err_detail, sizeof(s->err_detail), "%s ssl_err=%d errno=%d %s",
             where, ssl_err, errno, reason);
    ERR_clear_error();
}

static void pump_write(tm_ssl_stream *s) {
    if (s->state == TM_SS_STATE_CLOSED || s->inflight) return;
    for (;;) {
        uint8_t *chunk = tm_xmalloc(TM_SSL_WBUF_SIZE);
        int n = BIO_read(s->wbio, chunk, TM_SSL_WBUF_SIZE);
        if (n > 0) {
            tm_wreq *wr = tm_xcalloc(1, sizeof(*wr));
            wr->data = chunk;
            wr->s = s;
            uv_buf_t b = uv_buf_init((char *)chunk, (unsigned)n);
            int r;
            if (s->is_dtls) {
                r = uv_udp_send(&wr->ureq, s->udp, &b, 1, NULL,
                                (uv_udp_send_cb)on_write_done);
            } else {
                r = uv_write(&wr->req, s->tcp, &b, 1, on_write_done);
            }
            if (r != 0) {
                /* socket dead; notify */
                free(chunk);
                free(wr);
                s->last_err = TM_ERR_IO;
                finish_close(s);
                return;
            }
            s->inflight = true;
            return;
        }
        free(chunk);
        /* wbio empty: try to encrypt more plaintext */
        if (s->pq_off == s->pq_len) {
            s->pq_len = 0;
            s->pq_off = 0;
            if (s->above_low) {
                s->above_low = false;
                if (s->low_cb) s->low_cb(s, s->low_arg);
            }
            return;
        }
        size_t available = s->pq_len - s->pq_off;
        size_t write_len = s->ssl_retry_len ? s->ssl_retry_len
                                             : (available < 16384u ? available : 16384u);
        int w = SSL_write(s->ssl, s->pq + s->pq_off, (int)write_len);
        if (w > 0) {
            s->ssl_retry_len = 0;
            s->pq_off += (size_t)w;
            if (s->pq_off == s->pq_len) { s->pq_len = 0; s->pq_off = 0; }
            continue;
        }
        int e = SSL_get_error(s->ssl, w);
        if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
            /* OpenSSL requires the next SSL_write after WANT to use the same
               length and unchanged bytes. The queue may grow or move while
               the socket drains, so pin the length explicitly. */
            s->ssl_retry_len = write_len;
            return; /* resume on next event */
        }
        if (e == SSL_ERROR_ZERO_RETURN) {
            s->last_err = TM_ERR_EOF;
            finish_close(s);
            return;
        }
        record_tls_error(s, "pump_write", e);
        s->last_err = TM_ERR_TLS;
        finish_close(s);
        return;
    }
}

bool tm_ssl_stream_write_available(tm_ssl_stream *s) {
    return s->pq_len < TM_PQ_HIGH;
}

size_t tm_ssl_stream_pending(tm_ssl_stream *s) { return s->pq_len - s->pq_off; }

uint64_t tm_ssl_stream_write_total(tm_ssl_stream *s) { return s->write_pq_total; }

const char *tm_ssl_stream_error_detail(tm_ssl_stream *s) {
    return s && s->err_detail[0] ? s->err_detail : "";
}

bool tm_ssl_stream_drained(tm_ssl_stream *s) {
    /* nothing queued and the last encrypted chunk has been handed to
       the socket; pump_write always drains the wbio before returning
       with inflight false */
    return s->pq_off == s->pq_len && !s->inflight;
}

tm_status tm_ssl_stream_write(tm_ssl_stream *s, const uint8_t *data, size_t len) {
    if (s->state != TM_SS_STATE_OPEN || s->close_sent) return TM_ERR;
    if (s->pq_len + len > TM_PQ_HIGH) {
        s->above_low = true; /* ensure a drain low_cb later resumes reads */
        return TM_ERR_BUSY;
    }
    if (s->pq_len + len > TM_PQ_LOW) s->above_low = true;
    s->write_pq_total += len;
    if (s->pq_len + len > s->pq_cap) {
        size_t ncap = s->pq_cap ? s->pq_cap * 2 : 16384;
        while (ncap < s->pq_len + len) ncap *= 2;
        if (s->pq_off) {
            memmove(s->pq, s->pq + s->pq_off, s->pq_len - s->pq_off);
            s->pq_len -= s->pq_off;
            s->pq_off = 0;
        }
        s->pq = tm_xrealloc(s->pq, ncap);
        s->pq_cap = ncap;
    }
    memcpy(s->pq + s->pq_len, data, len);
    s->pq_len += len;
    pump_write(s);
    return TM_OK;
}

/* ------------------------- read path ------------------------------- */

static void promote_open(tm_ssl_stream *s) {
    s->state = TM_SS_STATE_OPEN;
    if (s->is_dtls) uv_timer_stop(&s->dtls_timer);
    if (s->cbs.handshake_cb) {
        tm_ssl_handshake_cb cb = s->cbs.handshake_cb;
        cb(s, 1, s->cbs.arg);
    }
}

static void pump_read_impl(tm_ssl_stream *s) {
    if (s->state == TM_SS_STATE_CLOSED) return;
    for (;;) {
        /* A read callback that pauses the stream means "stop handing me data";
           without this check the loop keeps delivering whatever is already
           decrypted and backpressure only takes effect a pass too late. */
        if (s->read_paused) return;
        int n = SSL_read(s->ssl, s->inbuf, (int)sizeof(s->inbuf));
        if (n > 0) {
            /* handshake may complete inside SSL_read; promote before
               delivering data so writers see OPEN state */
            if (s->state == TM_SS_STATE_HANDSHAKE &&
                SSL_is_init_finished(s->ssl)) {
                promote_open(s);
                if (s->state == TM_SS_STATE_CLOSED) return;
            }
            if (s->cbs.read_cb) s->cbs.read_cb(s, s->inbuf, (size_t)n, s->cbs.arg);
            continue;
        }
        if (n == 0) {
            /* peer close_notify */
            if (s->state == TM_SS_STATE_HANDSHAKE) {
                s->last_err = TM_ERR_EOF;
                finish_close(s);
                return;
            }
            if (s->cbs.eof_cb) s->cbs.eof_cb(s, s->cbs.arg);
            return;
        }
        int e = SSL_get_error(s->ssl, n);
        if (e == SSL_ERROR_WANT_READ) {
            if (s->state == TM_SS_STATE_HANDSHAKE) {
                if (SSL_is_init_finished(s->ssl)) {
                    promote_open(s);
                    if (s->state == TM_SS_STATE_CLOSED) return;
                }
                pump_write(s); /* flush any handshake flight */
            }
            return;
        }
        if (e == SSL_ERROR_WANT_WRITE) { pump_write(s); return; }
        if (e == SSL_ERROR_ZERO_RETURN) {
            if (s->cbs.eof_cb) s->cbs.eof_cb(s, s->cbs.arg);
            return;
        }
        record_tls_error(s, "pump_read", e);
        s->last_err = TM_ERR_TLS;
        finish_close(s);
        return;
    }
}

/* Read callbacks are allowed to close their owning relay.  Defer freeing the
   SSL stream until the SSL_read loop has unwound; otherwise a protocol error
   can free `s` at the callback boundary and the loop immediately dereferences
   it again. */
static void pump_read(tm_ssl_stream *s) {
    if (s->pumping_read) return;
    s->pumping_read = true;
    pump_read_impl(s);
    s->pumping_read = false;
    if (s->free_pending && !s->inflight) do_free(s);
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tm_ssl_stream *s = (tm_ssl_stream *)stream->data;
    (void)buf;
    if (!s) return;
    if (nread > 0) {
        BIO_write(s->rbio, buf->base, (int)nread);
        free(buf->base);
        pump_read(s);
        return;
    }
    free(buf->base);
    if (nread == UV_EOF) {
        /* abrupt TCP EOF without close_notify: treat as EOF, not protocol error,
           to keep relay semantics on the raw side */
        if (s->cbs.eof_cb) s->cbs.eof_cb(s, s->cbs.arg);
        return;
    }
    if (nread < 0) {
        s->last_err = TM_ERR_IO;
        finish_close(s);
    }
}

static void on_udp_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
    (void)addr;
    (void)flags;
    tm_ssl_stream *s = (tm_ssl_stream *)handle->data;
    if (!s) return;
    if (nread > 0) {
        BIO_write(s->rbio, buf->base, (int)nread);
        free(buf->base);
        pump_read(s);
        return;
    }
    free(buf->base);
    if (nread < 0) {
        s->last_err = TM_ERR_IO;
        finish_close(s);
    }
}

static void alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)handle;
    (void)suggested;
    buf->base = tm_xmalloc(TM_SSL_INBUF_SIZE);
    buf->len = TM_SSL_INBUF_SIZE;
}

static void udp_alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)handle;
    (void)suggested;
    buf->base = tm_xmalloc(TM_DEFAULT_DATAGRAM + 512u);
    buf->len = TM_DEFAULT_DATAGRAM + 512u;
}

/* ------------------------- handshake ------------------------------- */

static void dtls_timer_cb(uv_timer_t *t) {
    tm_ssl_stream *s = (tm_ssl_stream *)t->data;
    if (!s || s->state == TM_SS_STATE_CLOSED) return;
    struct timeval tv;
    if (DTLSv1_get_timeout(s->ssl, &tv) == 1) {
        if (tv.tv_sec == 0 && tv.tv_usec == 0) {
            DTLSv1_handle_timeout(s->ssl);
            pump_write(s);
        }
        if (s->state == TM_SS_STATE_CLOSED) return;
        uint64_t ms = (uint64_t)tv.tv_sec * 1000u + (uint64_t)(tv.tv_usec / 1000u);
        if (ms == 0) ms = 1;
        uv_timer_start(t, dtls_timer_cb, ms, 0);
        return;
    }
    /* no timeout pending */
    if (!SSL_is_init_finished(s->ssl)) {
        /* keep a slow poll while handshake incomplete */
        uv_timer_start(t, dtls_timer_cb, 500, 0);
    } else {
        uv_timer_stop(t);
    }
}

static void handshake_result(tm_ssl_stream *s, int r) {
    if (r == 1) {
        if (SSL_is_init_finished(s->ssl)) {
            promote_open(s);
            return;
        }
        /* more handshake data to exchange */
        pump_write(s);
        return;
    }
    int e = SSL_get_error(s->ssl, r);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
        pump_write(s);
        if (s->is_dtls) {
            struct timeval tv;
            uint64_t ms = 500;
            if (DTLSv1_get_timeout(s->ssl, &tv) == 1) {
                ms = (uint64_t)tv.tv_sec * 1000u + (uint64_t)(tv.tv_usec / 1000u);
                if (ms == 0) ms = 1;
            }
            uv_timer_start(&s->dtls_timer, dtls_timer_cb, ms, 0);
        }
        return;
    }
    s->last_err = TM_ERR_TLS;
    finish_close(s);
}

void tm_ssl_stream_handshake(tm_ssl_stream *s) {
    if (s->is_server) handshake_result(s, SSL_accept(s->ssl));
    else handshake_result(s, SSL_connect(s->ssl));
}

void tm_ssl_stream_start(tm_ssl_stream *s) {
    if (s->read_started) return;
    s->read_started = true;
    if (s->is_dtls) {
        s->udp->data = s;
        uv_udp_recv_start(s->udp, udp_alloc_cb, on_udp_recv);
    } else {
        s->tcp->data = s;
        uv_read_start(s->tcp, alloc_cb, on_read);
    }
}

/* Move all queued plaintext into the wbio, pumping the wbio out as it
   fills, and only then emit the close_notify so it lands after every
   byte on the wire. Continues from on_write_done while shutdown_pending. */
static void tls_try_shutdown(tm_ssl_stream *s) {
    while (s->pq_off < s->pq_len && s->state == TM_SS_STATE_OPEN) {
        size_t available = s->pq_len - s->pq_off;
        size_t write_len = s->ssl_retry_len ? s->ssl_retry_len
                                             : (available < 16384u ? available : 16384u);
        int w = SSL_write(s->ssl, s->pq + s->pq_off, (int)write_len);
        if (w > 0) {
            s->ssl_retry_len = 0;
            s->pq_off += (size_t)w;
            continue;
        }
        int e = SSL_get_error(s->ssl, w);
        if (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) {
            s->ssl_retry_len = write_len;
            pump_write(s); /* drains the wbio; may start a write */
            return; /* retry unchanged on the write/read event */
        }
        if (e == SSL_ERROR_ZERO_RETURN) {
            s->last_err = TM_ERR_EOF;
            finish_close(s);
            return;
        }
        s->last_err = TM_ERR_TLS;
        finish_close(s);
        return;
    }
    if (s->state != TM_SS_STATE_OPEN) return;
    /* Reset the read cursor too. Leaving pq_off behind makes pq_off > pq_len,
       which underflows tm_ssl_stream_pending(), keeps drained() false forever,
       and sends pump_write back into SSL_write after close_notify ("protocol
       is shutdown"). Only reachable when the queue was partly consumed, i.e.
       after sustained backpressure. */
    s->pq_len = 0;
    s->pq_off = 0;
    s->ssl_retry_len = 0;
    s->shutdown_pending = false;
    SSL_shutdown(s->ssl); /* sends close_notify; result handled by read path */
    pump_write(s);
}

void tm_ssl_stream_shutdown_send(tm_ssl_stream *s) {
    if (s->state != TM_SS_STATE_OPEN || s->close_sent) return;
    s->close_sent = true;
    s->shutdown_pending = true;
    tls_try_shutdown(s);
}

void tm_ssl_stream_set_low_cb(tm_ssl_stream *s, tm_ssl_low_cb cb, void *arg) {
    s->low_cb = cb;
    s->low_arg = arg;
}

void tm_ssl_stream_pause_read(tm_ssl_stream *s) {
    /* Stopping the socket is not enough: plaintext already decrypted into the
       SSL object would still be delivered by the pump. read_paused halts that
       loop too, so a paused relay really does stop receiving. */
    s->read_paused = true;
    if (!s->read_started || s->state == TM_SS_STATE_CLOSED) return;
    if (s->is_dtls) uv_udp_recv_stop(s->udp);
    else uv_read_stop(s->tcp);
}

void tm_ssl_stream_resume_read(tm_ssl_stream *s) {
    if (!s->read_paused) return;
    s->read_paused = false;
    if (!s->read_started || s->state == TM_SS_STATE_CLOSED) return;
    if (s->is_dtls) uv_udp_recv_start(s->udp, udp_alloc_cb, on_udp_recv);
    else uv_read_start(s->tcp, alloc_cb, on_read);
    /* Drain whatever was buffered inside the SSL object while paused; without
       this the stream can stall waiting for socket data that already arrived. */
    pump_read(s);
}

void tm_ssl_stream_close(tm_ssl_stream *s) {
    if (s->state == TM_SS_STATE_CLOSED) return;
    s->state = TM_SS_STATE_CLOSED;
    s->cbs.read_cb = NULL;
    s->cbs.eof_cb = NULL;
    s->cbs.error_cb = NULL;
    s->cbs.handshake_cb = NULL;
    if (s->read_started) {
        if (s->is_dtls) uv_udp_recv_stop(s->udp);
        else uv_read_stop(s->tcp);
    }
    if (s->inflight || s->pumping_read) {
        s->free_pending = true;
        return; /* freed by on_write_done or after the read callback unwinds */
    }
    do_free(s);
}
