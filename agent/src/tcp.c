#include "agent.h"
#include "tunnelmate/net.h"
#include "tunnelmate/crypto.h"
#include "tunnelmate/tls.h"

/* Data plane: for each OPEN_STREAM, connect a TLS 1.2 data connection to
   the broker, send DATA_BIND(sid, agent_secret), wait for DATA_BIND_OK,
   then connect the local service and relay with pause/resume backpressure
   and half-close. */

tm_astream *tm_astream_find(tm_agent_app *a, uint32_t sid) {
    for (tm_astream *st = a->streams; st; st = st->next)
        if (st->sid == sid) return st;
    return NULL;
}

static void astream_unlink(tm_agent_app *a, tm_astream *st) {
    tm_astream **pp = &a->streams;
    while (*pp) {
        if (*pp == st) { *pp = st->next; break; }
        pp = &(*pp)->next;
    }
    if (a->stream_count > 0) a->stream_count--;
}

static void stream_sock_closed(uv_handle_t *h) {
    tm_astream *st = (tm_astream *)h->data;
    if (--st->closing_refs == 0) free(st);
}

void tm_astream_close(tm_agent_app *a, tm_astream *st) {
    if (st->closing) return;
    st->closing = true;
    uv_timer_stop(&st->connect_timer);
    if (st->broker_io) { tm_io_close(st->broker_io); st->broker_io = NULL; }
    else if (st->broker_ssl) SSL_free(st->broker_ssl);
    st->broker_ssl = NULL;
    if (st->local_io) { tm_io_close(st->local_io); st->local_io = NULL; }
    tm_frame_reader_free(st->fr);
    st->fr = NULL;
    free(st->pending_buf);
    free(st->pend_buf);
    astream_unlink(a, st);
    tm_log_debug(a->log, "stream_closed", NULL, NULL,
                 "sid=%u up=%llu down=%llu bound=%d leof=%d beof=%d",
                 st->sid, (unsigned long long)st->up_bytes,
                 (unsigned long long)st->down_bytes, st->bound,
                 st->local_eof, st->broker_eof);
    st->closing_refs = 3;
    st->broker_sock.data = st;
    st->local_sock.data = st;
    st->connect_timer.data = st;
    uv_close((uv_handle_t *)&st->broker_sock, stream_sock_closed);
    uv_close((uv_handle_t *)&st->local_sock, stream_sock_closed);
    uv_close((uv_handle_t *)&st->connect_timer, stream_sock_closed);
}

static void flush_pend(tm_io *io, uint8_t **buf, size_t *len, size_t *cap);

/* ---------------------- relay callbacks ----------------------------- */

/* close only once both sides have EOF'd AND every queued byte has been
   handed to the sockets; dropping a leg with unsent data loses the tail */
static void astream_maybe_close(tm_astream *st) {
    if (st->closing || !st->local_eof || !st->broker_eof) return;
    if (st->local_io && !tm_io_drained(st->local_io)) return;
    if (st->broker_io && !tm_io_drained(st->broker_io)) return;
    if (st->pending_len || st->pend_len) return;
    tm_astream_close(st->a, st);
}

static void relay_broker_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io;
    if (st->closing) return;
    st->up_bytes += len;
    if (!st->local_io) {
        /* local connect still in flight: queue until bound */
        if (st->pending_len + len > TM_IO_HIGH_WATER + 65536u) {
            tm_astream_close(st->a, st);
            return;
        }
        if (st->pending_len + len > st->pending_cap) {
            size_t ncap = st->pending_cap ? st->pending_cap * 2 : 16384;
            while (ncap < st->pending_len + len) ncap *= 2;
            st->pending_buf = tm_xrealloc(st->pending_buf, ncap);
            st->pending_cap = ncap;
        }
        memcpy(st->pending_buf + st->pending_len, data, len);
        st->pending_len += len;
        if (st->pending_len >= TM_IO_HIGH_WATER) {
            tm_io_pause_read(st->broker_io);
            st->broker_paused = true;
        }
        return;
    }
    int r = tm_io_write(st->local_io, data, len);
    if (r == TM_ERR_BUSY) {
        if (st->pending_len + len > st->pending_cap) {
            size_t ncap = st->pending_cap ? st->pending_cap * 2 : 16384;
            while (ncap < st->pending_len + len) ncap *= 2;
            st->pending_buf = tm_xrealloc(st->pending_buf, ncap);
            st->pending_cap = ncap;
        }
        memcpy(st->pending_buf + st->pending_len, data, len);
        st->pending_len += len;
        tm_io_pause_read(st->broker_io);
        st->broker_paused = true;
    } else if (r != TM_OK) {
        tm_astream_close(st->a, st);
    }
}

static void relay_broker_eof(tm_io *io, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io;
    if (st->closing) return;
    st->broker_eof = true;
    if (!st->local_io) return; /* flushed once local connects */
    flush_pend(st->local_io, &st->pending_buf, &st->pending_len, &st->pending_cap);
    flush_pend(st->broker_io, &st->pend_buf, &st->pend_len, &st->pend_cap);
    if (st->pending_len) { astream_maybe_close(st); return; }
    st->local_fin = true;
    tm_io_shutdown_send(st->local_io);
    astream_maybe_close(st);
}

static void relay_broker_error(tm_io *io, int err, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io; (void)err;
    tm_astream_close(st->a, st);
}

static void flush_pend(tm_io *io, uint8_t **buf, size_t *len, size_t *cap);
static void flush_pend(tm_io *io, uint8_t **buf, size_t *len, size_t *cap) {
    while (*len) {
        size_t n = *len < 65536 ? *len : 65536;
        int r = tm_io_write(io, *buf, n);
        if (r == TM_ERR_BUSY) return;
        if (r != TM_OK) {
            free(*buf);
            *buf = NULL;
            *len = *cap = 0;
            return;
        }
        memmove(*buf, *buf + n, *len - n);
        *len -= n;
        if (!*len) { free(*buf); *buf = NULL; *cap = 0; }
    }
}

static void relay_broker_low(tm_io *io, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io;
    if (st->closing) return;
    flush_pend(st->broker_io, &st->pend_buf, &st->pend_len, &st->pend_cap);
    if (st->pend_len) { astream_maybe_close(st); return; }
    if (st->local_eof && !st->broker_fin) {
        st->broker_fin = true;
        tm_io_shutdown_send(st->broker_io);
    }
    if (st->local_paused) {
        st->local_paused = false;
        tm_io_resume_read(st->local_io);
    }
    astream_maybe_close(st);
}

static void relay_local_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io;
    if (st->closing) return;
    st->down_bytes += len;
    int r = tm_io_write(st->broker_io, data, len);
    if (r == TM_ERR_BUSY) {
        if (st->pend_len + len > st->pend_cap) {
            size_t ncap = st->pend_cap ? st->pend_cap * 2 : 16384;
            while (ncap < st->pend_len + len) ncap *= 2;
            st->pend_buf = tm_xrealloc(st->pend_buf, ncap);
            st->pend_cap = ncap;
        }
        memcpy(st->pend_buf + st->pend_len, data, len);
        st->pend_len += len;
        tm_io_pause_read(st->local_io);
        st->local_paused = true;
    } else if (r != TM_OK) {
        tm_astream_close(st->a, st);
    }
}

static void relay_local_eof(tm_io *io, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io;
    if (st->closing) return;
    st->local_eof = true;
    flush_pend(st->broker_io, &st->pend_buf, &st->pend_len, &st->pend_cap);
    if (st->pend_len) { astream_maybe_close(st); return; }
    st->broker_fin = true;
    tm_io_shutdown_send(st->broker_io);
    astream_maybe_close(st);
}

static void relay_local_error(tm_io *io, int err, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io; (void)err;
    tm_astream_close(st->a, st);
}

static void relay_local_low(tm_io *io, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io;
    if (st->closing) return;
    flush_pend(st->local_io, &st->pending_buf, &st->pending_len, &st->pending_cap);
    if (st->pending_len) { astream_maybe_close(st); return; }
    if (st->broker_eof && !st->local_fin) {
        st->local_fin = true;
        tm_io_shutdown_send(st->local_io);
    }
    if (st->broker_paused) {
        st->broker_paused = false;
        tm_io_resume_read(st->broker_io);
    }
    astream_maybe_close(st);
}

/* ---------------------- local connect ------------------------------- */

static void local_connected(uv_connect_t *req, int status) {
    tm_astream *st = (tm_astream *)req->handle->data;
    st->connecting = false;
    if (st->closing) return; /* freed via stream_sock_closed */
    if (status != 0) {
        uint8_t err[] = "local connect failed";
        tm_agent_send_frame(st->a, tm_frame_make(TM_MSG_OPEN_STREAM_ERROR,
                                                 st->sid, err, sizeof(err) - 1));
        tm_astream_close(st->a, st);
        return;
    }
    uv_timer_stop(&st->connect_timer);
    st->local_io = tm_io_tcp_new(st->a->loop, &st->local_sock, &(tm_io_cbs){
        .read_cb = relay_local_read,
        .eof_cb = relay_local_eof,
        .error_cb = relay_local_error,
        .low_cb = relay_local_low,
        .arg = st,
    });
    tm_io_start(st->local_io);
    tm_io_start(st->broker_io);
    st->bound = true;
    /* Deliver pre-bind bytes incrementally. A single write larger than the
       downstream high watermark would be rejected even though the relay can
       drain it safely in bounded chunks. relay_local_low continues the flush. */
    flush_pend(st->local_io, &st->pending_buf, &st->pending_len,
               &st->pending_cap);
    if (st->pending_len) {
        tm_io_pause_read(st->broker_io);
        st->broker_paused = true;
    } else if (st->broker_paused) {
        st->broker_paused = false;
        tm_io_resume_read(st->broker_io);
    }
    if (st->broker_eof) {
        tm_io_shutdown_send(st->local_io);
        if (st->local_eof) tm_astream_close(st->a, st);
    }
    tm_log_debug(st->a->log, "stream_bound", NULL, NULL, "sid=%u", st->sid);
}

static void local_connect_timeout(uv_timer_t *t) {
    tm_astream *st = (tm_astream *)t->data;
    if (!st || st->closing || st->bound) return;
    uint8_t err[] = "local connect timeout";
    tm_agent_send_frame(st->a, tm_frame_make(TM_MSG_OPEN_STREAM_ERROR,
                                             st->sid, err, sizeof(err) - 1));
    tm_astream_close(st->a, st);
}

/* ---------------------- broker data conn ---------------------------- */

/* first frames on the data connection: DATA_BIND, then DATA_BIND_OK */
static void data_conn_pre_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    tm_agent_app *a = st->a;
    (void)io;
    if (st->bound) { relay_broker_read(io, data, len, arg); return; }
    bool err = false;
    tm_frame *f = tm_frame_reader_feed(st->fr, data, len, &err);
    if (err) { tm_astream_close(a, st); return; }
    while (f) {
        if (f->type == TM_MSG_DATA_BIND_OK && f->stream_id == st->sid) {
            tm_frame_free(f);
            st->broker_io = io;
            /* switch to raw relay once bound; buffer any leftover */
            size_t n = 0;
            uint8_t *lo = tm_frame_reader_drain(st->fr, &n);
            st->pending_buf = lo;
            st->pending_len = n;
            tm_io_set_cbs(io, &(tm_io_cbs){
                .ready_cb = NULL, .read_cb = relay_broker_read,
                .eof_cb = relay_broker_eof, .error_cb = relay_broker_error,
                .low_cb = relay_broker_low, .arg = st,
            });
            uv_tcp_init(a->loop, &st->local_sock);
            st->local_sock.data = st;
            st->connecting = true;
            int r = tm_tcp_connect(a->loop, &st->local_sock, a->cfg.local_host,
                                   a->cfg.local_port, local_connected, st);
            if (r != TM_OK) {
                uint8_t e[] = "local connect failed";
                tm_agent_send_frame(a, tm_frame_make(TM_MSG_OPEN_STREAM_ERROR,
                                                     st->sid, e, sizeof(e) - 1));
                tm_astream_close(a, st);
                return;
            }
            uv_timer_start(&st->connect_timer, local_connect_timeout,
                           (uint64_t)a->cfg.local_connect_timeout_ms, 0);
            return;
        }
        if (f->type == TM_MSG_DATA_BIND_ERROR || f->type == TM_MSG_DATA_BIND) {
            tm_frame_free(f);
            tm_astream_close(a, st);
            return;
        }
        tm_frame_free(f);
        f = tm_frame_reader_feed(st->fr, NULL, 0, &err);
        if (err) { tm_astream_close(a, st); return; }
    }
}

static void data_conn_ready(tm_io *io, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    tm_agent_app *a = st->a;
    st->broker_io = io;
    uint8_t *payload = tm_xmalloc(TM_MAX_SECRET);
    size_t slen = strlen(a->cfg.agent_secret);
    memcpy(payload, a->cfg.agent_secret, slen);
    tm_frame *f = tm_frame_make(TM_MSG_DATA_BIND, st->sid,
                                payload, (uint32_t)slen);
    free(payload);
    size_t len = 0;
    uint8_t *buf = tm_frame_encode(f, &len);
    tm_frame_free(f);
    if (!buf) { tm_astream_close(a, st); return; }
    /* DATA_BIND travels on the DATA connection, not the control conn */
    if (tm_io_write(io, buf, len) != TM_OK) {
        free(buf);
        tm_astream_close(a, st);
        return;
    }
    free(buf);
}

static void data_conn_error(tm_io *io, int err, void *arg) {
    (void)io; (void)err;
    tm_astream *st = (tm_astream *)arg;
    tm_astream_close(st->a, st);
}

static void data_conn_eof(tm_io *io, void *arg) {
    tm_astream *st = (tm_astream *)arg;
    (void)io;
    if (!st->bound) tm_astream_close(st->a, st);
    else relay_broker_eof(io, arg);
}

static void data_conn_connected(uv_connect_t *req, int status) {
    tm_astream *st = (tm_astream *)req->handle->data;
    st->connecting = false;
    if (st->closing) return; /* freed via stream_sock_closed */
    if (status != 0) {
        uint8_t e[] = "broker connect failed";
        tm_agent_send_frame(st->a, tm_frame_make(TM_MSG_OPEN_STREAM_ERROR,
                                                 st->sid, e, sizeof(e) - 1));
        tm_astream_close(st->a, st);
        return;
    }
    tm_io_start(st->broker_io);
    tm_io_handshake(st->broker_io);
}

/* ---------------------- open handler -------------------------------- */

void tm_astream_open(tm_agent_app *a, uint32_t sid) {
    if (tm_astream_find(a, sid)) return; /* duplicate */
    tm_astream *st = tm_xcalloc(1, sizeof(*st));
    st->sid = sid;
    st->a = a;
    st->created_ms = tm_now_ms();
    st->fr = tm_frame_reader_new();
    uv_timer_init(a->loop, &st->connect_timer);
    st->connect_timer.data = st;
    uv_tcp_init(a->loop, &st->local_sock);
    st->local_sock.data = st;
    st->next = a->streams;
    a->streams = st;
    a->stream_count++;

    uv_tcp_init(a->loop, &st->broker_sock);
    st->broker_sock.data = st;
    st->broker_ssl = SSL_new(a->tls_ctx);
    if (!st->broker_ssl) { tm_astream_close(a, st); return; }
    if (tm_tls_configure_client_ssl(st->broker_ssl, a->cfg.broker_host,
                                    a->cfg.verify_ca) != TM_OK) {
        tm_astream_close(a, st);
        return;
    }
    st->broker_io = tm_io_ssl_new(a->loop, (uv_stream_t *)&st->broker_sock,
                                  st->broker_ssl, false, false, &(tm_io_cbs){
                                      .ready_cb = data_conn_ready,
                                      .read_cb = data_conn_pre_read,
                                      .eof_cb = data_conn_eof,
                                      .error_cb = data_conn_error,
                                      .low_cb = relay_broker_low,
                                      .arg = st,
                                  });
    st->connecting = true;
    int r = tm_tcp_connect(a->loop, &st->broker_sock, a->cfg.broker_host,
                           a->cfg.broker_port, data_conn_connected, st);
    if (r != TM_OK) {
        tm_astream_close(a, st);
        return;
    }
    tm_log_debug(a->log, "data_conn_open", NULL, NULL, "sid=%u", sid);
}
