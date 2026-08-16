#include "agent.h"
#include "tunnelmate/net.h"
#include "tunnelmate/crypto.h"

/* Control connection lifecycle: connect (with backoff), TLS 1.3 handshake,
   HELLO/REGISTER, heartbeat, frame dispatch, reconnect on drop. */

static void ctl_handshake_done(tm_io *io, void *arg);
static void ctl_read(tm_io *io, const uint8_t *data, size_t len, void *arg);
static void ctl_eof(tm_io *io, void *arg);
static void ctl_error(tm_io *io, int err, void *arg);
static void agent_hb_timer_cb(uv_timer_t *t);
static void reconnect_timer_cb(uv_timer_t *t);

void tm_agent_send_frame(tm_agent_app *a, tm_frame *f) {
    if (!a->ctl_io) { tm_frame_free(f); return; }
    size_t len;
    uint8_t *buf = tm_frame_encode(f, &len);
    tm_frame_free(f);
    if (!buf) return;
    if (tm_io_write(a->ctl_io, buf, len) != TM_OK) {
        free(buf);
        tm_agent_disconnect(a, "send failed");
        return;
    }
    free(buf);
}

static void ctl_handshake_timeout(uv_timer_t *t) {
    tm_agent_app *a = (tm_agent_app *)t->data;
    if (a && a->connected) tm_agent_disconnect(a, "handshake timeout");
}

static void ctl_connected(uv_connect_t *req, int status) {
    tm_agent_app *a = (tm_agent_app *)req->handle->data;
    if (status != 0) {
        tm_log_warn(a->log, "connect_failed", NULL, NULL, "%s:%u (%s)",
                    a->cfg.broker_host, (unsigned)a->cfg.broker_port,
                    uv_strerror(status));
        tm_agent_disconnect(a, "connect failed");
        return;
    }
    a->ctl_ssl = SSL_new(a->tls_ctx);
    if (!a->ctl_ssl) { tm_agent_disconnect(a, "ssl_new"); return; }
    a->ctl_io = tm_io_ssl_new(a->loop, (uv_stream_t *)&a->ctl_sock, a->ctl_ssl,
                              false, true, &(tm_io_cbs){
                                  .ready_cb = ctl_handshake_done,
                                  .read_cb = ctl_read,
                                  .eof_cb = ctl_eof,
                                  .error_cb = ctl_error,
                                  .arg = a,
                              });
    tm_io_start(a->ctl_io);
    tm_io_handshake(a->ctl_io);
    uv_timer_start(&a->hs_timer, ctl_handshake_timeout,
                   (uint64_t)a->cfg.handshake_timeout_ms, 0);
    a->connected = true;
}

static void ctl_handshake_done(tm_io *io, void *arg) {
    tm_agent_app *a = (tm_agent_app *)arg;
    (void)io;
    uv_timer_stop(&a->hs_timer);
    a->last_rx_ms = tm_now_ms();
    a->last_ping_ms = a->last_rx_ms;
    tm_log_info(a->log, "control_tls_ready", NULL, NULL, "%s:%u",
                a->cfg.broker_host, (unsigned)a->cfg.broker_port);
    tm_agent_send_frame(a, tm_frame_make(TM_MSG_HELLO, 0,
                                         (const uint8_t *)TM_PROTO_STRING,
                                         TM_PROTO_STRING_LEN));
}

static void ctl_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_agent_app *a = (tm_agent_app *)arg;
    (void)io;
    a->last_rx_ms = tm_now_ms();
    bool err = false;
    tm_frame *f = tm_frame_reader_feed(a->ctl_fr, data, len, &err);
    if (err) { tm_agent_disconnect(a, "malformed frame"); return; }
    while (f) {
        switch (f->type) {
        case TM_MSG_HELLO_ACK:
            if (!a->got_hello) {
                a->got_hello = true;
                uint8_t reg[2 + TM_MAX_TUNNEL_ID + TM_MAX_SECRET];
                size_t idlen = strlen(a->cfg.tunnel_id);
                if (idlen == 0 || idlen > TM_TUNNEL_ID_LEN ||
                    strlen(a->cfg.agent_secret) == 0) {
                    tm_log_error(a->log, "bad_config", NULL, NULL,
                                 "tunnel_id and agent_secret required");
                    tm_agent_shutdown(a);
                    tm_frame_free(f);
                    return;
                }
                size_t slen = strlen(a->cfg.agent_secret);
                wr_u16(reg, (uint16_t)idlen);
                memcpy(reg + 2, a->cfg.tunnel_id, idlen);
                memcpy(reg + 2 + idlen, a->cfg.agent_secret, slen);
                tm_agent_send_frame(a, tm_frame_make(TM_MSG_REGISTER, 0, reg,
                                                     (uint32_t)(2 + idlen + slen)));
            }
            break;
        case TM_MSG_REGISTER_OK:
            if (!a->registered) {
                a->registered = true;
                tm_log_info(a->log, "registered", NULL, NULL, "tunnel=%s port=%s",
                            a->cfg.tunnel_id, a->cfg.local_host);
                uv_timer_start(&a->hb_timer, agent_hb_timer_cb,
                               (uint64_t)a->cfg.heartbeat_interval_ms, 0);
            }
            break;
        case TM_MSG_REGISTER_ERROR:
            tm_log_error(a->log, "register_rejected", NULL, NULL,
                         "%.*s", (int)f->payload_len, f->payload);
            tm_agent_disconnect(a, "register rejected");
            break;
        case TM_MSG_PING:
            tm_agent_send_frame(a, tm_frame_make(TM_MSG_PONG, 0, NULL, 0));
            break;
        case TM_MSG_PONG:
            break;
        case TM_MSG_OPEN_STREAM:
            if (a->registered) tm_astream_open(a, f->stream_id);
            break;
        case TM_MSG_CLOSE_STREAM: {
            tm_astream *st = tm_astream_find(a, f->stream_id);
            if (st) tm_astream_close(a, st);
            break;
        }
        case TM_MSG_GOING_AWAY:
            tm_log_info(a->log, "going_away", NULL, NULL, "broker shutting down");
            tm_agent_shutdown(a);
            break;
        default:
            break;
        }
        tm_frame_free(f);
        f = tm_frame_reader_feed(a->ctl_fr, NULL, 0, &err);
        if (err) { tm_agent_disconnect(a, "malformed frame"); return; }
    }
}

static void ctl_eof(tm_io *io, void *arg) {
    (void)io;
    tm_agent_app *a = (tm_agent_app *)arg;
    tm_agent_disconnect(a, "eof");
}

static void ctl_error(tm_io *io, int err, void *arg) {
    (void)io; (void)err;
    tm_agent_app *a = (tm_agent_app *)arg;
    tm_agent_disconnect(a, "connection error");
}

static void agent_hb_timer_cb(uv_timer_t *t) {
    tm_agent_app *a = (tm_agent_app *)t->data;
    if (!a || a->shutting_down) return;
    uint64_t now = tm_now_ms();
    if (now - a->last_rx_ms > (uint64_t)a->cfg.idle_timeout_ms) {
        tm_log_warn(a->log, "control_idle_timeout", NULL, NULL, "reconnecting");
        tm_agent_disconnect(a, "idle timeout");
        return;
    }
    if (now - a->last_ping_ms >= (uint64_t)a->cfg.heartbeat_interval_ms) {
        a->last_ping_ms = now;
        tm_agent_send_frame(a, tm_frame_make(TM_MSG_PING, 0, NULL, 0));
    }
}

void tm_agent_disconnect(tm_agent_app *a, const char *reason) {
    if (!a->connected && !a->registered) return;
    bool was_registered = a->registered;
    tm_log_info(a->log, "disconnected", NULL, NULL, "reason=%s", reason);
    if (a->ctl_io) { tm_io_close(a->ctl_io); a->ctl_io = NULL; }
    else if (a->ctl_ssl) { SSL_free(a->ctl_ssl); }
    a->ctl_ssl = NULL;
    if (!uv_is_closing((uv_handle_t *)&a->ctl_sock))
        uv_close((uv_handle_t *)&a->ctl_sock, NULL);
    tm_frame_reader_free(a->ctl_fr);
    a->ctl_fr = tm_frame_reader_new();
    uv_timer_stop(&a->hb_timer);
    uv_timer_stop(&a->hs_timer);
    a->connected = false;
    a->registered = false;
    a->got_hello = false;
    if (was_registered) {
        /* close all streams + udp session; they die with the control conn */
        tm_astream *st = a->streams;
        while (st) {
            tm_astream *nxt = st->next;
            tm_astream_close(a, st);
            st = nxt;
        }
        tm_agent_udp_stop(a);
    }
    if (a->shutting_down) return;
    /* schedule reconnect with backoff */
    a->reconnect_delay_ms = a->reconnect_delay_ms * 2;
    if (a->reconnect_delay_ms > (uint64_t)a->cfg.reconnect_max_delay_ms)
        a->reconnect_delay_ms = (uint64_t)a->cfg.reconnect_max_delay_ms;
    uv_timer_start(&a->reconnect_timer, reconnect_timer_cb, a->reconnect_delay_ms, 0);
}

static void reconnect_timer_cb(uv_timer_t *t) {
    tm_agent_app *a = (tm_agent_app *)t->data;
    if (a && !a->shutting_down) tm_agent_connect(a);
}

void tm_agent_connect(tm_agent_app *a) {
    if (a->shutting_down || a->connected) return;
    a->reconnect_delay_ms = (uint64_t)a->cfg.reconnect_delay_ms;
    int r = tm_tcp_connect(a->loop, &a->ctl_sock, a->cfg.broker_host,
                           a->cfg.broker_port, ctl_connected, a);
    if (r != TM_OK) {
        tm_log_warn(a->log, "resolve_failed", NULL, NULL, "%s", a->cfg.broker_host);
        uv_timer_start(&a->reconnect_timer, reconnect_timer_cb,
                       a->reconnect_delay_ms, 0);
        return;
    }
    tm_log_info(a->log, "connecting", NULL, NULL, "%s:%u",
                a->cfg.broker_host, (unsigned)a->cfg.broker_port);
}