#include "peer.h"
#include "tunnelmate/crypto.h"
#include "tunnelmate/net.h"
#include "tunnelmate/tls.h"

/* Per-session TCP relay for closed tunnels. A local consumer connection is
   mapped one-to-one onto a broker connection that authenticates with the
   shared token (HELLO/AUTH), opens a stream (DATA_BIND 0), and — after
   DATA_BIND_OK — relays raw bytes with backpressure and half-close. */

static void sess_unlink(tm_peer *p, tm_psess *s) {
    tm_psess **pp = &p->sessions;
    while (*pp) {
        if (*pp == s) { *pp = s->next; break; }
        pp = &(*pp)->next;
    }
}

static void sess_sock_closed(uv_handle_t *h) {
    tm_psess *s = (tm_psess *)h->data;
    if (--s->closing_refs == 0) free(s);
}

void tm_psess_close(tm_peer *p, tm_psess *s) {
    if (s->closing) return;
    s->closing = true;
    uv_timer_stop(&s->hs_timer);
    if (s->broker_io) { tm_io_close(s->broker_io); s->broker_io = NULL; }
    else if (s->broker_ssl) SSL_free(s->broker_ssl);
    s->broker_ssl = NULL;
    if (s->local_io) { tm_io_close(s->local_io); s->local_io = NULL; }
    tm_frame_reader_free(s->fr);
    s->fr = NULL;
    free(s->pending_buf);
    free(s->pend_buf);
    sess_unlink(p, s);
    s->closing_refs = 3;
    s->broker_sock.data = s;
    s->local_sock.data = s;
    s->hs_timer.data = s;
    uv_close((uv_handle_t *)&s->broker_sock, sess_sock_closed);
    uv_close((uv_handle_t *)&s->local_sock, sess_sock_closed);
    uv_close((uv_handle_t *)&s->hs_timer, sess_sock_closed);
}

/* close only once both sides have EOF'd AND every queued byte has been
   handed to the sockets; dropping a leg with unsent data loses the tail */
static void psess_maybe_close(tm_psess *s) {
    if (s->closing || !s->local_eof || !s->broker_eof) return;
    if (s->local_io && !tm_io_drained(s->local_io)) return;
    if (s->broker_io && !tm_io_drained(s->broker_io)) return;
    if (s->pending_len || s->pend_len) return;
    tm_psess_close(s->p, s);
}

static void flush_pend(tm_io *io, uint8_t **buf, size_t *len, size_t *cap,
                       bool *in_progress);

/* ---------------------- relay callbacks ----------------------------- */

static void relay_broker_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    (void)io;
    if (s->closing) return;
    if (!s->local_io) {
        /* local connect still in flight: queue until bound */
        if (s->pending_len + len > TM_IO_HIGH_WATER) {
            tm_psess_close(s->p, s);
            return;
        }
        if (s->pending_len + len > s->pending_cap) {
            size_t ncap = s->pending_cap ? s->pending_cap * 2 : 16384;
            while (ncap < s->pending_len + len) ncap *= 2;
            s->pending_buf = tm_xrealloc(s->pending_buf, ncap);
            s->pending_cap = ncap;
        }
        memcpy(s->pending_buf + s->pending_len, data, len);
        s->pending_len += len;
        return;
    }
    /* Never overtake bytes already queued in pending_buf. */
    int r = s->pending_len ? TM_ERR_BUSY
                           : tm_io_write(s->local_io, data, len);
    if (r == TM_ERR_BUSY) {
        if (s->pending_len + len > s->pending_cap) {
            size_t ncap = s->pending_cap ? s->pending_cap * 2 : 16384;
            while (ncap < s->pending_len + len) ncap *= 2;
            s->pending_buf = tm_xrealloc(s->pending_buf, ncap);
            s->pending_cap = ncap;
        }
        memcpy(s->pending_buf + s->pending_len, data, len);
        s->pending_len += len;
        tm_io_pause_read(s->broker_io);
        s->broker_paused = true;
    } else if (r != TM_OK) {
        tm_psess_close(s->p, s);
    }
}

static void relay_broker_eof(tm_io *io, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    (void)io;
    if (s->closing) return;
    s->broker_eof = true;
    if (!s->local_io) return; /* flushed once local binds */
    flush_pend(s->local_io, &s->pending_buf, &s->pending_len, &s->pending_cap,
               &s->flushing_local);
    flush_pend(s->broker_io, &s->pend_buf, &s->pend_len, &s->pend_cap,
               &s->flushing_broker);
    if (s->pending_len) { psess_maybe_close(s); return; }
    s->local_fin = true;
    tm_io_shutdown_send(s->local_io);
    psess_maybe_close(s);
}

static void relay_broker_error(tm_io *io, int err, void *arg) {
    (void)io; (void)err;
    tm_psess *s = (tm_psess *)arg;
    tm_psess_close(s->p, s);
}

/* See the broker relay: tm_io_write can drain synchronously and fire the
   low-water callback, re-entering this function on the same buffer. The guard
   stops the inner pass from consuming the slice the outer loop still holds,
   which would otherwise duplicate some bytes and skip others. */
static void flush_pend(tm_io *io, uint8_t **buf, size_t *len, size_t *cap,
                       bool *in_progress) {
    if (*in_progress) return;
    *in_progress = true;
    while (*len) {
        size_t n = *len < 65536 ? *len : 65536;
        int r = tm_io_write(io, *buf, n);
        if (r == TM_ERR_BUSY) break;
        if (r != TM_OK) {
            free(*buf);
            *buf = NULL;
            *len = *cap = 0;
            break;
        }
        memmove(*buf, *buf + n, *len - n);
        *len -= n;
        if (!*len) { free(*buf); *buf = NULL; *cap = 0; }
    }
    *in_progress = false;
}

static void relay_broker_low(tm_io *io, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    (void)io;
    if (s->closing) return;
    flush_pend(s->broker_io, &s->pend_buf, &s->pend_len, &s->pend_cap,
               &s->flushing_broker);
    if (s->pend_len) { psess_maybe_close(s); return; }
    if (s->local_eof && !s->broker_fin) {
        s->broker_fin = true;
        tm_io_shutdown_send(s->broker_io);
    }
    if (s->local_paused) {
        s->local_paused = false;
        tm_io_resume_read(s->local_io);
    }
    psess_maybe_close(s);
}

static void relay_local_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    (void)io;
    if (s->closing) return;
    /* Same ordering invariant as the local leg. */
    int r = s->pend_len ? TM_ERR_BUSY
                        : tm_io_write(s->broker_io, data, len);
    if (r == TM_ERR_BUSY) {
        if (s->pend_len + len > s->pend_cap) {
            size_t ncap = s->pend_cap ? s->pend_cap * 2 : 16384;
            while (ncap < s->pend_len + len) ncap *= 2;
            s->pend_buf = tm_xrealloc(s->pend_buf, ncap);
            s->pend_cap = ncap;
        }
        memcpy(s->pend_buf + s->pend_len, data, len);
        s->pend_len += len;
        tm_io_pause_read(s->local_io);
        s->local_paused = true;
    } else if (r != TM_OK) {
        tm_psess_close(s->p, s);
    }
}

static void relay_local_eof(tm_io *io, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    (void)io;
    if (s->closing) return;
    s->local_eof = true;
    flush_pend(s->broker_io, &s->pend_buf, &s->pend_len, &s->pend_cap,
               &s->flushing_broker);
    if (s->pend_len) { psess_maybe_close(s); return; }
    s->broker_fin = true;
    tm_io_shutdown_send(s->broker_io);
    psess_maybe_close(s);
}

static void relay_local_error(tm_io *io, int err, void *arg) {
    (void)io; (void)err;
    tm_psess *s = (tm_psess *)arg;
    tm_psess_close(s->p, s);
}

static void relay_local_low(tm_io *io, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    (void)io;
    if (s->closing) return;
    flush_pend(s->local_io, &s->pending_buf, &s->pending_len, &s->pending_cap,
               &s->flushing_local);
    if (s->pending_len) { psess_maybe_close(s); return; }
    if (s->broker_eof && !s->local_fin) {
        s->local_fin = true;
        tm_io_shutdown_send(s->local_io);
    }
    if (s->broker_paused) {
        s->broker_paused = false;
        tm_io_resume_read(s->broker_io);
    }
    psess_maybe_close(s);
}

/* ---------------------- broker connection --------------------------- */

static void sess_send_frame(tm_peer *p, tm_psess *s, tm_frame *f) {
    if (s->closing || !s->broker_io) { tm_frame_free(f); return; }
    size_t len;
    uint8_t *buf = tm_frame_encode(f, &len);
    tm_frame_free(f);
    if (!buf) return;
    if (tm_io_write(s->broker_io, buf, len) != TM_OK) {
        free(buf);
        tm_psess_close(p, s);
        return;
    }
    free(buf);
}

/* broker frames until DATA_BIND_OK, then raw relay */
static void sess_pre_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    tm_peer *p = s->p;
    (void)io;
    if (s->bound) { relay_broker_read(io, data, len, arg); return; }
    bool err = false;
    tm_frame *f = tm_frame_reader_feed(s->fr, data, len, &err);
    if (err) { tm_psess_close(p, s); return; }
    while (f) {
        switch (f->type) {
        case TM_MSG_HELLO_ACK:
            if (!s->got_hello) {
                s->got_hello = true;
                uint8_t reg[2 + TM_MAX_TUNNEL_ID + TM_MAX_SECRET];
                size_t idlen = strlen(p->cfg.tunnel_id);
                size_t tlen = strlen(p->cfg.token);
                wr_u16(reg, (uint16_t)idlen);
                memcpy(reg + 2, p->cfg.tunnel_id, idlen);
                memcpy(reg + 2 + idlen, p->cfg.token, tlen);
                sess_send_frame(p, s, tm_frame_make(TM_MSG_AUTH, 0, reg,
                                                    (uint32_t)(2 + idlen + tlen)));
            }
            break;
        case TM_MSG_AUTH_OK:
            if (s->got_hello)
                sess_send_frame(p, s, tm_frame_make(TM_MSG_DATA_BIND, 0, NULL, 0));
            break;
        case TM_MSG_DATA_BIND_OK:
            if (f->stream_id == 0 && s->got_hello) {
                tm_frame_free(f);
                size_t n = 0;
                uint8_t *lo = tm_frame_reader_drain(s->fr, &n);
                s->pending_buf = lo;
                s->pending_len = n;
                s->bound = true;
                uv_timer_stop(&s->hs_timer);
                tm_io_set_cbs(io, &(tm_io_cbs){
                    .ready_cb = NULL, .read_cb = relay_broker_read,
                    .eof_cb = relay_broker_eof, .error_cb = relay_broker_error,
                    .low_cb = relay_broker_low, .arg = s,
                });
                s->local_io = tm_io_tcp_new(p->loop, &s->local_sock, &(tm_io_cbs){
                    .read_cb = relay_local_read,
                    .eof_cb = relay_local_eof,
                    .error_cb = relay_local_error,
                    .low_cb = relay_local_low,
                    .arg = s,
                });
                tm_io_start(s->local_io);
                if (s->pending_buf) {
                    tm_io_write(s->local_io, s->pending_buf, s->pending_len);
                    free(s->pending_buf);
                    s->pending_buf = NULL;
                    s->pending_len = 0;
                }
                tm_log_debug(p->log, "peer_stream_bound", NULL, NULL,
                             "tunnel=%s", p->cfg.tunnel_id);
                return;
            }
            break;
        case TM_MSG_AUTH_ERROR:
        case TM_MSG_DATA_BIND_ERROR:
            tm_log_error(p->log, "peer_rejected", NULL, NULL,
                         "tunnel=%s (%.*s)", p->cfg.tunnel_id,
                         (int)f->payload_len, f->payload);
            tm_frame_free(f);
            tm_psess_close(p, s);
            return;
        case TM_MSG_GOING_AWAY:
        case TM_MSG_ERROR:
            tm_frame_free(f);
            tm_psess_close(p, s);
            return;
        default:
            break;
        }
        tm_frame_free(f);
        f = tm_frame_reader_feed(s->fr, NULL, 0, &err);
        if (err) { tm_psess_close(p, s); return; }
    }
}

static void sess_ready(tm_io *io, void *arg) {
    (void)io;
    tm_psess *s = (tm_psess *)arg;
    sess_send_frame(s->p, s, tm_frame_make(TM_MSG_HELLO, 0,
                                           (const uint8_t *)TM_PROTO_STRING,
                                           TM_PROTO_STRING_LEN));
}

static void sess_hs_timeout(uv_timer_t *t) {
    tm_psess *s = (tm_psess *)t->data;
    if (s && !s->bound && !s->closing)
        tm_psess_close(s->p, s);
}

static void sess_eof(tm_io *io, void *arg) {
    tm_psess *s = (tm_psess *)arg;
    if (!s->bound) tm_psess_close(s->p, s);
    else relay_broker_eof(io, arg);
}

static void sess_error(tm_io *io, int err, void *arg) {
    (void)io; (void)err;
    tm_psess *s = (tm_psess *)arg;
    tm_psess_close(s->p, s);
}

static void broker_connected(uv_connect_t *req, int status) {
    tm_psess *s = (tm_psess *)req->handle->data;
    s->connecting = false;
    if (s->closing) return; /* freed via sess_sock_closed */
    if (status != 0) { tm_psess_close(s->p, s); return; }
    s->broker_ssl = SSL_new(s->p->tls_ctx);
    if (!s->broker_ssl) { tm_psess_close(s->p, s); return; }
    if (tm_tls_configure_client_ssl(s->broker_ssl, s->p->cfg.broker_host,
                                    s->p->cfg.verify_ca) != TM_OK) {
        tm_psess_close(s->p, s);
        return;
    }
    /* TLS 1.2: the stream must honor half-close on the relay */
    s->broker_io = tm_io_ssl_new(s->p->loop, (uv_stream_t *)&s->broker_sock,
                                  s->broker_ssl, false, false, &(tm_io_cbs){
                                      .ready_cb = sess_ready,
                                      .read_cb = sess_pre_read,
                                      .eof_cb = sess_eof,
                                      .error_cb = sess_error,
                                      .low_cb = relay_broker_low,
                                      .arg = s,
                                  });
    tm_io_start(s->broker_io);
    tm_io_handshake(s->broker_io);
    uv_timer_start(&s->hs_timer, sess_hs_timeout,
                   (uint64_t)s->p->cfg.handshake_timeout_ms, 0);
}

/* ---------------------- local listener ------------------------------ */

static void on_local_accept(uv_stream_t *server, int status) {
    tm_peer *p = (tm_peer *)server->data;
    if (status != 0) return;
    if (p->shutting_down) return;

    tm_psess *s = tm_xcalloc(1, sizeof(*s));
    s->p = p;
    s->fr = tm_frame_reader_new();
    uv_timer_init(p->loop, &s->hs_timer);
    s->hs_timer.data = s;
    uv_tcp_init(p->loop, &s->local_sock);
    s->local_sock.data = s;
    tm_tcp_tune(&s->local_sock);
    if (uv_accept(server, (uv_stream_t *)&s->local_sock) != 0) {
        uv_timer_stop(&s->hs_timer);
        uv_close((uv_handle_t *)&s->hs_timer, NULL);
        tm_frame_reader_free(s->fr);
        free(s);
        return;
    }

    s->connecting = true;
    int r = tm_tcp_connect(p->loop, &s->broker_sock, p->cfg.broker_host,
                           p->cfg.broker_port, broker_connected, s);
    if (r != TM_OK) {
        tm_psess_close(p, s);
        return;
    }
    s->next = p->sessions;
    p->sessions = s;
    tm_log_debug(p->log, "local_accept", NULL, NULL, "tunnel=%s",
                 p->cfg.tunnel_id);
}

int tm_peer_tcp_listen(tm_peer *p) {
    uv_tcp_init(p->loop, &p->listener);
    p->listener.data = p;
    struct sockaddr_storage sa;
    if (tm_addr_parse(p->cfg.listen_host, p->cfg.listen_port, &sa) != TM_OK) {
        tm_log_error(p->log, "bad_listen_host", NULL, NULL, "%s",
                     p->cfg.listen_host);
        return 1;
    }
    int r = uv_tcp_bind(&p->listener, (const struct sockaddr *)&sa, 0);
    if (r != 0) {
        tm_log_error(p->log, "bind_failed", NULL, NULL,
                     "%s port=%u (%s)", p->cfg.listen_host,
                     (unsigned)p->cfg.listen_port, uv_strerror(r));
        return 1;
    }
    if (uv_listen((uv_stream_t *)&p->listener, 128, on_local_accept) != 0) {
        tm_log_error(p->log, "listen_failed", NULL, NULL,
                     "%s port=%u", p->cfg.listen_host,
                     (unsigned)p->cfg.listen_port);
        return 1;
    }
    p->listening = true;
    tm_log_info(p->log, "peer_listening", NULL, NULL,
                "%s:%u -> tunnel=%s broker=%s:%u", p->cfg.listen_host,
                (unsigned)p->cfg.listen_port, p->cfg.tunnel_id,
                p->cfg.broker_host, (unsigned)p->cfg.broker_port);
    return 0;
}
