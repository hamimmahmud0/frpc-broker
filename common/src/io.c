#include "tunnelmate/io.h"
#include "tunnelmate/tls.h"
#include "tunnelmate/common.h"
#include "tunnelmate/net.h"

#include <openssl/err.h>
#include <errno.h>

#define TM_IO_KIND_TCP 0
#define TM_IO_KIND_SSL 1

/* ------------------------------------------------------------------ */
/* raw TCP                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    tm_io io;
    tm_io_cbs cbs;
    uv_tcp_t *tcp;   /* borrowed; caller owns and closes the handle */
    bool reading;
    bool write_closed;
    bool closed;
    uint8_t *wb;
    size_t wb_len, wb_cap, wb_off;
    size_t in_flight;   /* bytes handed to uv_write, not yet acked */
    uv_write_t wreq;
    bool wreq_pending;
    bool free_after_wreq;
    bool above_low;
    bool fin_sent;
    uint64_t queued_total;  /* bytes accepted by tcp_write */
} tm_io_tcp;

static void tcp_write_done(uv_write_t *req, int status);

static void tcp_maybe_low(tm_io_tcp *t) {
    /* fire on every drain-to-empty: the relay's low_cb checks its own
       pending buffers and no-ops when nothing is queued, so this stays
       cheap; relying on above_low alone stalls flush chains whose
       pieces never cross the low-water mark */
    if (t->wb_len == 0 && t->cbs.low_cb) t->cbs.low_cb(&t->io, t->cbs.arg);
}

static void tcp_shutdown_done(uv_shutdown_t *req, int status) {
    (void)status;
    free(req);
}

static void tcp_fin(tm_io_tcp *t) {
    if (t->fin_sent) return;
    t->fin_sent = true;
    uv_shutdown_t *req = tm_xcalloc(1, sizeof(*req));
    req->data = t;
    uv_shutdown(req, (uv_stream_t *)t->tcp, tcp_shutdown_done);
}

static void tcp_pump(tm_io_tcp *t) {
    if (t->wreq_pending || t->closed) return;
    if (t->wb_off == t->wb_len) {
        t->wb_len = 0;
        t->wb_off = 0;
        tcp_maybe_low(t);
        if (t->write_closed && t->wb_len == 0) tcp_fin(t);
        return;
    }
    if (t->write_closed && t->fin_sent) {
        return; /* no data after FIN */
    }
    t->in_flight = t->wb_len - t->wb_off;
    uv_buf_t b = uv_buf_init((char *)t->wb + t->wb_off, (unsigned)t->in_flight);
    t->wreq.data = t;
    int r = uv_write(&t->wreq, (uv_stream_t *)t->tcp, &b, 1, tcp_write_done);
    if (r != 0) {
        t->wreq_pending = true; tcp_write_done(&t->wreq, r);
    }
    else t->wreq_pending = true;
}

static void tcp_write_done(uv_write_t *req, int status) {
    tm_io_tcp *t = (tm_io_tcp *)req->data;
    if (!t) return;
    t->wreq_pending = false;
    /* only the bytes captured by uv_write are complete; data appended
       while the write was in flight stays queued */
    t->wb_off += t->in_flight;
    t->in_flight = 0;
    if (t->wb_off == t->wb_len) {
        t->wb_len = 0;
        t->wb_off = 0;
    }
    if (t->free_after_wreq) {
        free(t->wb);
        free(t);
        return;
    }
    if (status != 0 && status != UV_ECANCELED) {
        if (t->cbs.error_cb && !t->closed) t->cbs.error_cb(&t->io, TM_ERR_IO, t->cbs.arg);
        return;
    }
    tcp_maybe_low(t);
    tcp_pump(t);
}

static void tcp_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    tm_io_tcp *t = (tm_io_tcp *)stream->data;
    if (!t) return;
    if (nread > 0) {
        if (t->cbs.read_cb) {
            t->cbs.read_cb(&t->io, (uint8_t *)buf->base, (size_t)nread, t->cbs.arg);
        }
        free(buf->base);
        return;
    }
    free(buf->base);
    if (nread == UV_EOF) {
        if (t->cbs.eof_cb) t->cbs.eof_cb(&t->io, t->cbs.arg);
        return;
    }
    if (nread < 0) {
        if (t->cbs.error_cb && !t->closed) t->cbs.error_cb(&t->io, TM_ERR_IO, t->cbs.arg);
    }
}

static void tcp_alloc_cb(uv_handle_t *h, size_t suggested, uv_buf_t *buf) {
    (void)h; (void)suggested;
    buf->base = tm_xmalloc(65536);
    buf->len = 65536;
}

/* Borrow an already-initialized uv_tcp_t (from accept or connect). The
   caller owns the handle and must uv_close it; the io never closes it. */
tm_io *tm_io_tcp_new(uv_loop_t *loop, uv_tcp_t *tcp, const tm_io_cbs *cbs) {
    (void)loop;
    tm_io_tcp *t = tm_xcalloc(1, sizeof(*t));
    t->io.kind = TM_IO_KIND_TCP;
    t->io.impl = t;
    t->cbs = *cbs;
    t->tcp = tcp;
    tcp->data = t;
    return &t->io;
}

static void tcp_close(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    if (t->closed) return;
    t->closed = true;
    if (t->reading) uv_read_stop((uv_stream_t *)t->tcp);
    if (t->wreq_pending) {
        t->free_after_wreq = true;
        uv_cancel((uv_req_t *)&t->wreq);
        return;
    }
    free(t->wb);
    free(t);
}

static void tcp_start(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    if (t->reading) return;
    t->reading = true;
    uv_read_start((uv_stream_t *)t->tcp, tcp_alloc_cb, tcp_read_cb);
}

static int tcp_write(tm_io *io, const uint8_t *data, size_t len) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    if (t->closed || t->write_closed) return TM_ERR;
    if (t->wb_len + len > TM_IO_HIGH_WATER) {
        t->above_low = true; /* ensure a drain low_cb later resumes reads */
        return TM_ERR_BUSY;
    }
    if (t->wb_len + len > t->wb_cap) {
        /* the in-flight uv_write reads straight out of wb: the buffer
           must not move until the write completes */
        if (t->wreq_pending) {
            t->above_low = true;
            return TM_ERR_BUSY;
        }
        if (t->wb_off) {
            memmove(t->wb, t->wb + t->wb_off, t->wb_len - t->wb_off);
            t->wb_len -= t->wb_off;
            t->wb_off = 0;
        }
        size_t ncap = t->wb_cap ? t->wb_cap * 2 : 65536;
        while (ncap < t->wb_len + len) ncap *= 2;
        t->wb = tm_xrealloc(t->wb, ncap);
        t->wb_cap = ncap;
    }
    memcpy(t->wb + t->wb_len, data, len);
    t->wb_len += len;
    t->queued_total += len;
    if (t->wb_len > TM_IO_LOW_WATER) t->above_low = true;
    tcp_pump(t);
    return TM_OK;
}

static void tcp_shutdown_send(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    if (t->closed || t->write_closed) return;
    t->write_closed = true;
    if (t->wreq_pending || t->wb_len != 0) return; /* FIN after drain */
    tcp_fin(t);
}

static bool tcp_write_available(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    return t->wb_len < TM_IO_LOW_WATER;
}

static void tcp_pause_read(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    if (t->reading && !t->closed) uv_read_stop((uv_stream_t *)t->tcp);
}

static void tcp_resume_read(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    if (t->reading && !t->closed) uv_read_start((uv_stream_t *)t->tcp, tcp_alloc_cb, tcp_read_cb);
}

static size_t tcp_pending(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    return t->wb_len - t->wb_off;
}

static bool tcp_drained(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    return !t->wreq_pending && t->wb_len - t->wb_off == 0;
}

static bool tcp_open(tm_io *io) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    return !t->closed;
}

/* ------------------------------------------------------------------ */
/* TLS / DTLS legs                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    tm_io io;
    tm_io_cbs cbs;
    uv_stream_t *sock; /* borrowed */
    uv_udp_t *udp;     /* borrowed */
    tm_ssl_stream *ssl;
    bool closed;
} tm_io_ssl;

static void ssl_low_cb(tm_ssl_stream *s, void *arg) {
    (void)s;
    tm_io_ssl *t = (tm_io_ssl *)arg;
    if (t->cbs.low_cb) t->cbs.low_cb(&t->io, t->cbs.arg);
}

static void ssl_read_cb(tm_ssl_stream *s, const uint8_t *data, size_t len, void *arg) {
    (void)s;
    tm_io_ssl *t = (tm_io_ssl *)arg;
    if (t->cbs.read_cb) t->cbs.read_cb(&t->io, data, len, t->cbs.arg);
}
static void ssl_eof_cb(tm_ssl_stream *s, void *arg) {
    (void)s;
    tm_io_ssl *t = (tm_io_ssl *)arg;
    if (t->cbs.eof_cb) t->cbs.eof_cb(&t->io, t->cbs.arg);
}
static void ssl_error_cb(tm_ssl_stream *s, int err, void *arg) {
    (void)s;
    tm_io_ssl *t = (tm_io_ssl *)arg;
    if (t->cbs.error_cb && !t->closed) t->cbs.error_cb(&t->io, err, t->cbs.arg);
}
static void ssl_handshake_cb(tm_ssl_stream *s, int ok, void *arg) {
    (void)s;
    tm_io_ssl *t = (tm_io_ssl *)arg;
    if (ok) { if (t->cbs.ready_cb) t->cbs.ready_cb(&t->io, t->cbs.arg); }
    else if (t->cbs.error_cb && !t->closed) t->cbs.error_cb(&t->io, TM_ERR_TLS, t->cbs.arg);
}

tm_io *tm_io_ssl_new(uv_loop_t *loop, uv_stream_t *sock, SSL *ssl,
                     bool is_server, bool tls13, const tm_io_cbs *cbs) {
    tm_io_ssl *t = tm_xcalloc(1, sizeof(*t));
    t->io.kind = TM_IO_KIND_SSL;
    t->io.impl = t;
    t->cbs = *cbs;
    t->sock = sock;
    tm_ssl_cbs sc = { .handshake_cb = ssl_handshake_cb, .read_cb = ssl_read_cb,
                      .eof_cb = ssl_eof_cb, .error_cb = ssl_error_cb, .arg = t };
    if (!tls13) {
        SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
        SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
    }
    t->ssl = tm_ssl_stream_new(loop, sock, ssl, is_server, &sc);
    tm_ssl_stream_set_low_cb(t->ssl, ssl_low_cb, t);
    return &t->io;
}

tm_io *tm_io_dtls_new(uv_loop_t *loop, uv_udp_t *udp, SSL *ssl,
                      bool is_server, const tm_io_cbs *cbs) {
    tm_io_ssl *t = tm_xcalloc(1, sizeof(*t));
    t->io.kind = TM_IO_KIND_SSL;
    t->io.impl = t;
    t->cbs = *cbs;
    t->udp = udp;
    tm_ssl_cbs sc = { .handshake_cb = ssl_handshake_cb, .read_cb = ssl_read_cb,
                      .eof_cb = ssl_eof_cb, .error_cb = ssl_error_cb, .arg = t };
    t->ssl = tm_dtls_stream_new(loop, udp, ssl, is_server, &sc);
    tm_ssl_stream_set_low_cb(t->ssl, ssl_low_cb, t);
    return &t->io;
}

static void ssl_start(tm_io *io) { tm_ssl_stream_start(((tm_io_ssl *)io->impl)->ssl); }
static void ssl_handshake(tm_io *io) { tm_ssl_stream_handshake(((tm_io_ssl *)io->impl)->ssl); }
static int ssl_write(tm_io *io, const uint8_t *data, size_t len) {
    tm_io_ssl *t = (tm_io_ssl *)io->impl;
    if (t->closed) return TM_ERR;
    return tm_ssl_stream_write(t->ssl, data, len);
}
static void ssl_shutdown_send(tm_io *io) {
    tm_ssl_stream_shutdown_send(((tm_io_ssl *)io->impl)->ssl);
}
static void ssl_pause_read(tm_io *io) {
    tm_ssl_stream_pause_read(((tm_io_ssl *)io->impl)->ssl);
}
static void ssl_resume_read(tm_io *io) {
    tm_ssl_stream_resume_read(((tm_io_ssl *)io->impl)->ssl);
}
static bool ssl_write_available(tm_io *io) {
    return tm_ssl_stream_write_available(((tm_io_ssl *)io->impl)->ssl);
}
static size_t ssl_pending(tm_io *io) {
    return tm_ssl_stream_pending(((tm_io_ssl *)io->impl)->ssl);
}
static bool ssl_drained(tm_io *io) {
    return tm_ssl_stream_drained(((tm_io_ssl *)io->impl)->ssl);
}
static bool ssl_open(tm_io *io) {
    tm_io_ssl *t = (tm_io_ssl *)io->impl;
    return !t->closed;
}
static bool ssl_is_tls(tm_io *io) { (void)io; return true; }

static void ssl_close(tm_io *io) {
    tm_io_ssl *t = (tm_io_ssl *)io->impl;
    if (t->closed) return;
    t->closed = true;
    tm_ssl_stream_close(t->ssl);
    free(t);
}

static void tcp_set_cbs(tm_io *io, const tm_io_cbs *cbs) {
    tm_io_tcp *t = (tm_io_tcp *)io->impl;
    t->cbs = *cbs;
}

static void ssl_set_cbs(tm_io *io, const tm_io_cbs *cbs) {
    tm_io_ssl *t = (tm_io_ssl *)io->impl;
    t->cbs = *cbs;
}

/* ------------------------------------------------------------------ */
/* dispatch                                                            */
/* ------------------------------------------------------------------ */

static const struct tm_io_ops {
    void (*start)(tm_io *);
    void (*handshake)(tm_io *);
    int (*write)(tm_io *, const uint8_t *, size_t);
    void (*shutdown_send)(tm_io *);
    bool (*write_available)(tm_io *);
    size_t (*pending)(tm_io *);
    bool (*drained)(tm_io *);
    bool (*open)(tm_io *);
    bool (*is_tls)(tm_io *);
    void (*close)(tm_io *);
    void (*pause_read)(tm_io *);
    void (*resume_read)(tm_io *);
    void (*set_cbs)(tm_io *, const tm_io_cbs *);
} ops[2] = {
    { tcp_start, NULL, tcp_write, tcp_shutdown_send, tcp_write_available,
      tcp_pending, tcp_drained, tcp_open, NULL, tcp_close, tcp_pause_read, tcp_resume_read, tcp_set_cbs },
    { ssl_start, ssl_handshake, ssl_write, ssl_shutdown_send, ssl_write_available,
      ssl_pending, ssl_drained, ssl_open, ssl_is_tls, ssl_close, ssl_pause_read, ssl_resume_read, ssl_set_cbs },
};

static const struct tm_io_ops *io_ops(tm_io *io) { return &ops[io->kind]; }

/* A relay leg is set to NULL the moment it is closed, and the surviving leg can
   still have callbacks queued against it. Every entry point therefore treats a
   NULL io as "already gone" and returns the closed-side answer rather than
   dereferencing it. */
void tm_io_start(tm_io *io) { if (io) io_ops(io)->start(io); }
void tm_io_handshake(tm_io *io) {
    if (io && io_ops(io)->handshake) io_ops(io)->handshake(io);
}
int tm_io_write(tm_io *io, const uint8_t *data, size_t len) {
    if (!io) return TM_ERR;
    return io_ops(io)->write(io, data, len);
}
void tm_io_shutdown_send(tm_io *io) { if (io) io_ops(io)->shutdown_send(io); }
void tm_io_pause_read(tm_io *io) {
    if (io && io_ops(io)->pause_read) io_ops(io)->pause_read(io);
}
void tm_io_resume_read(tm_io *io) {
    if (io && io_ops(io)->resume_read) io_ops(io)->resume_read(io);
}
void tm_io_set_cbs(tm_io *io, const tm_io_cbs *cbs) {
    if (io) io_ops(io)->set_cbs(io, cbs);
}
bool tm_io_write_available(tm_io *io) { return io ? io_ops(io)->write_available(io) : false; }
size_t tm_io_pending(tm_io *io) { return io ? io_ops(io)->pending(io) : 0; }
bool tm_io_drained(tm_io *io) { return io ? io_ops(io)->drained(io) : true; }
bool tm_io_is_open(tm_io *io) { return io ? io_ops(io)->open(io) : false; }
bool tm_io_is_tls(tm_io *io) {
    return io && io_ops(io)->is_tls ? io_ops(io)->is_tls(io) : false;
}
void tm_io_close(tm_io *io) { if (io) io_ops(io)->close(io); }

const char *tm_io_error_detail(tm_io *io) {
    if (io && io->kind == TM_IO_KIND_SSL) {
        tm_io_ssl *t = (tm_io_ssl *)io->impl;
        return t->ssl ? tm_ssl_stream_error_detail(t->ssl) : "";
    }
    return "";
}

uint64_t tm_io_write_total(tm_io *io) {
    if (!io) return 0;
    if (io->kind == TM_IO_KIND_TCP) {
        tm_io_tcp *t = (tm_io_tcp *)io->impl;
        return t->queued_total;
    }
    if (io->kind == TM_IO_KIND_SSL) {
        tm_io_ssl *t = (tm_io_ssl *)io->impl;
        return t->ssl ? tm_ssl_stream_write_total(t->ssl) : 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* connect helper                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    uv_connect_t req;
    uv_connect_cb cb;
} tm_connect_req;

static void connect_cb(uv_connect_t *req, int status) {
    tm_connect_req *cr = (tm_connect_req *)req;
    cr->cb(req, status);
    free(cr);
}

void tm_tcp_tune(uv_tcp_t *tcp) {
    /* Nagle batches small writes and, against a peer using delayed ACKs, adds
       roughly 40 ms to every small request/response. A relay forwards whatever
       chunk sizes the application produces, so it must not add that delay: the
       application decides its own batching. */
    uv_tcp_nodelay(tcp, 1);
}

tm_status tm_tcp_connect(uv_loop_t *loop, uv_tcp_t *tcp, const char *host,
                         uint16_t port, uv_connect_cb cb, void *arg) {
    struct sockaddr_storage sa;
    if (tm_addr_parse(host, port, &sa) != TM_OK) return TM_ERR_INVALID;
    uv_tcp_init(loop, tcp);
    tm_tcp_tune(tcp);
    tcp->data = arg;
    tm_connect_req *cr = tm_xcalloc(1, sizeof(*cr));
    cr->cb = cb;
    int r = uv_tcp_connect(&cr->req, tcp, (const struct sockaddr *)&sa, connect_cb);
    if (r != 0) { free(cr); return TM_ERR; }
    return TM_OK;
}
