#include "broker.h"
#include "tunnelmate/crypto.h"
#include "tunnelmate/net.h"

/* The control port carries every TLS connection to the broker. The role of a
   connection is decided by its first frame:
     HELLO               -> control session; the next frame selects the role
                            (REGISTER = agent, AUTH = closed-tunnel peer)
     DATA_BIND(sid)      -> agent data connection for a pending stream
   Agent control sessions are promoted to tm_agent and heartbeat via PING;
   closed-tunnel peers authenticate with the tunnel's shared token and open
   streams with DATA_BIND(0), handing their connection to the relay as leg A.
   The TLS version is left at the context range (1.2-1.3) so the agent's
   control connections negotiate TLS 1.3 and its data connections (which
   require 1.2 for half-close) negotiate TLS 1.2. */

#define TM_MAX_PENDING_CONNS 4096

/* ------------------------------------------------------------------ */
/* pending control-port connections                                    */
/* ------------------------------------------------------------------ */

struct tm_conn {
    tm_broker *b;
    uv_tcp_t *sock;
    SSL *ssl;
    tm_io *io;
    tm_frame_reader *fr;
    uv_timer_t hs_timer;
    uint64_t last_rx_ms;
    char remote[128];
    bool got_hello;
    bool peer_authed;
    tm_tunnel *peer_tun;
    tm_agent *promoted;
    bool closing;
    tm_conn *next;
};

static void conn_close(tm_conn *c, const char *why);
static void control_tick_cb(uv_timer_t *t);

static void conn_unlink(tm_conn *c) {
    tm_conn **pp = &c->b->conns;
    while (*pp) {
        if (*pp == c) { *pp = c->next; break; }
        pp = &(*pp)->next;
    }
}

/* the timer handle is embedded; its close callback frees the conn */
static void conn_free_cb(uv_handle_t *h) { free(h->data); }

static void send_frame_raw(tm_broker *b, tm_io *io, uint8_t type, uint32_t sid,
                           const char *msg) {
    if (!io) return;
    size_t n = msg ? strlen(msg) : 0;
    tm_frame *f = tm_frame_make(type, sid, (const uint8_t *)msg, (uint32_t)n);
    if (!f) { b->protocol_errors++; return; }
    size_t len;
    uint8_t *buf = tm_frame_encode(f, &len);
    tm_frame_free(f);
    if (!buf) { b->protocol_errors++; return; }
    int r = tm_io_write(io, buf, len);
    free(buf);
    if (r != TM_OK) b->protocol_errors++;
}

/* ------------------------------------------------------------------ */
/* agent control sessions                                              */
/* ------------------------------------------------------------------ */

void tm_agent_drop(tm_broker *b, tm_agent *a, const char *reason) {
    if (!a || a->closing) return;
    a->closing = true;
    if (a->tun && a->tun->agent == a) {
        a->tun->agent = NULL;
        a->tun->agent_online = false;
    }
    tm_log_info(b->log, "agent_dropped", "reason", reason,
                "tunnel=%s remote=%s", a->tun ? a->tun->id : "?",
                a->remote[0] ? a->remote : "?");
    if (a->io) { tm_io_close(a->io); a->io = NULL; }
    if (a->sock && !uv_is_closing((uv_handle_t *)a->sock))
        uv_close((uv_handle_t *)a->sock, tm_broker_tls_free_handle_cb);
    a->sock = NULL;
    if (a->fr) { tm_frame_reader_free(a->fr); a->fr = NULL; }
    free(a);
}

void tm_agent_send_frame(tm_broker *b, tm_agent *a, tm_frame *f) {
    if (!a || a->closing || !a->io) { tm_frame_free(f); return; }
    size_t len;
    uint8_t *buf = tm_frame_encode(f, &len);
    tm_frame_free(f);
    if (!buf) return;
    if (tm_io_write(a->io, buf, len) != TM_OK) {
        free(buf);
        tm_agent_drop(b, a, "send failed");
        return;
    }
    free(buf);
}

static void agent_conn_read(tm_io *io, const uint8_t *data, size_t len,
                            void *arg) {
    tm_agent *a = (tm_agent *)arg;
    (void)io;
    a->last_rx_ms = tm_now_ms();
    bool err = false;
    tm_frame *f = tm_frame_reader_feed(a->fr, data, len, &err);
    if (err) { tm_agent_drop(a->b, a, "malformed frame"); return; }
    while (f) {
        switch (f->type) {
        case TM_MSG_PING:
            tm_agent_send_frame(a->b, a, tm_frame_make(TM_MSG_PONG, 0, NULL, 0));
            break;
        case TM_MSG_PONG:
            break;
        case TM_MSG_OPEN_STREAM_ERROR:
        case TM_MSG_CLOSE_STREAM:
        case TM_MSG_KILL_STREAM: {
            tm_stream *st = tm_stream_find(a->b, a->tun, f->stream_id);
            if (st) tm_stream_close(a->b, st);
            break;
        }
        default:
            break;
        }
        tm_frame_free(f);
        f = tm_frame_reader_feed(a->fr, NULL, 0, &err);
        if (err) { tm_agent_drop(a->b, a, "malformed frame"); return; }
    }
}

static void agent_conn_eof(tm_io *io, void *arg) {
    (void)io;
    tm_agent *a = (tm_agent *)arg;
    tm_agent_drop(a->b, a, "eof");
}

static void agent_conn_error(tm_io *io, int err, void *arg) {
    (void)io; (void)err;
    tm_agent *a = (tm_agent *)arg;
    tm_agent_drop(a->b, a, "connection error");
}

static void agent_register(tm_conn *c, tm_frame *f) {
    tm_broker *b = c->b;
    if (f->payload_len < 3 ||
        f->payload_len > 2 + TM_TUNNEL_ID_LEN + TM_MAX_SECRET) {
        send_frame_raw(b, c->io, TM_MSG_REGISTER_ERROR, 0, "bad register");
        conn_close(c, "bad register");
        return;
    }
    uint16_t idlen = rd_u16(f->payload);
    if (idlen == 0 || (size_t)2 + idlen > f->payload_len) {
        send_frame_raw(b, c->io, TM_MSG_REGISTER_ERROR, 0, "bad register");
        conn_close(c, "bad register");
        return;
    }
    size_t slen = f->payload_len - 2 - idlen;
    if (slen == 0) {
        send_frame_raw(b, c->io, TM_MSG_REGISTER_ERROR, 0, "bad register");
        conn_close(c, "bad register");
        return;
    }
    char id[TM_TUNNEL_ID_LEN + 1];
    memcpy(id, f->payload + 2, idlen);
    id[idlen] = '\0';

    tm_tunnel *tun = tm_tunnel_find(b, id);

    /* An unknown tunnel and a wrong secret must be indistinguishable, in both
       the reply text and the work performed. Always derive the HMAC and run a
       constant-time comparison — against an unsatisfiable reference when the
       tunnel does not exist — so registration cannot be used to enumerate
       tunnel IDs. */
    static const char never_matches[65] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    uint8_t hmac[32];
    char hex[65];
    tm_hmac_sha256(b->hmac_key, sizeof(b->hmac_key),
                   f->payload + 2 + idlen, slen, hmac);
    tm_sha256_hex(hmac, 32, hex);
    const char *expected = (tun && tun->enabled) ? tun->agent_secret_hmac : never_matches;
    bool secret_ok = tm_ct_eq_hex(hex, expected);
    if (!tun || !tun->enabled || !secret_ok) {
        b->failed_auths++;
        send_frame_raw(b, c->io, TM_MSG_REGISTER_ERROR, 0, "bad credentials");
        conn_close(c, "register rejected");
        return;
    }

    /* promote the conn to an agent control session */
    tm_agent *a = tm_xcalloc(1, sizeof(*a));
    a->b = b;
    a->tun = tun;
    a->sock = c->sock;
    a->io = c->io;
    a->fr = c->fr;
    a->remote[0] = '\0';
    snprintf(a->remote, sizeof(a->remote), "%s", c->remote);
    a->last_rx_ms = tm_now_ms();
    a->last_ping_ms = a->last_rx_ms;
    a->got_hello = true;
    c->sock = NULL;
    c->io = NULL;
    c->fr = NULL;

    if (tun->agent) {
        b->agent_reconnects++;
        tm_agent_drop(b, tun->agent, "replaced");
    }
    tun->agent = a;
    tun->agent_online = true;
    tun->last_seen_ms = a->last_rx_ms;

    tm_io_set_cbs(a->io, &(tm_io_cbs){
        .ready_cb = NULL, .read_cb = agent_conn_read,
        .eof_cb = agent_conn_eof, .error_cb = agent_conn_error, .arg = a,
    });

    send_frame_raw(b, a->io, TM_MSG_REGISTER_OK, 0, NULL);
    tm_log_info(b->log, "agent_registered", "tunnel_id", NULL,
                "%s remote=%s port=%u", tun->id, a->remote,
                (unsigned)tun->public_port);

    c->promoted = a;
    conn_unlink(c);
    uv_timer_stop(&c->hs_timer);
    uv_close((uv_handle_t *)&c->hs_timer, conn_free_cb);
}

/* ------------------------------------------------------------------ */
/* closed-tunnel peers                                                 */
/* ------------------------------------------------------------------ */

static void peer_auth(tm_conn *c, tm_frame *f) {
    tm_broker *b = c->b;
    if (f->payload_len < 3 ||
        f->payload_len > 2 + TM_TUNNEL_ID_LEN + TM_MAX_SECRET) {
        b->failed_auths++;
        send_frame_raw(b, c->io, TM_MSG_AUTH_ERROR, 0, "bad credentials");
        conn_close(c, "bad auth");
        return;
    }
    uint16_t idlen = rd_u16(f->payload);
    if (idlen == 0 || (size_t)2 + idlen > f->payload_len) {
        b->failed_auths++;
        send_frame_raw(b, c->io, TM_MSG_AUTH_ERROR, 0, "bad credentials");
        conn_close(c, "bad auth");
        return;
    }
    size_t slen = f->payload_len - 2 - idlen;
    if (slen == 0) {
        b->failed_auths++;
        send_frame_raw(b, c->io, TM_MSG_AUTH_ERROR, 0, "bad credentials");
        conn_close(c, "bad auth");
        return;
    }
    char id[TM_TUNNEL_ID_LEN + 1];
    memcpy(id, f->payload + 2, idlen);
    id[idlen] = '\0';

    tm_tunnel *tun = tm_tunnel_find(b, id);

    /* As in register_frame: do the same work and give the same answer whether
       or not the tunnel exists, so a peer cannot probe for valid tunnel IDs. */
    static const char never_matches[65] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    bool usable = tun && tun->closed && tun->enabled &&
                  tun->shared_token_hmac[0] != '\0';
    uint8_t hmac[32];
    char hex[65];
    tm_hmac_sha256(b->hmac_key, sizeof(b->hmac_key),
                   f->payload + 2 + idlen, slen, hmac);
    tm_sha256_hex(hmac, 32, hex);
    const char *expected = usable ? tun->shared_token_hmac : never_matches;
    bool token_ok = tm_ct_eq_hex(hex, expected);
    if (!usable || !token_ok) {
        b->failed_auths++;
        send_frame_raw(b, c->io, TM_MSG_AUTH_ERROR, 0, "bad credentials");
        conn_close(c, "bad auth");
        return;
    }

    c->peer_authed = true;
    c->peer_tun = tun;
    send_frame_raw(b, c->io, TM_MSG_AUTH_OK, 0, NULL);
    tm_log_info(b->log, "peer_authenticated", "tunnel_id", NULL, "%s", tun->id);
}

/* DATA_BIND(0): the authenticated peer opens a stream; its TLS connection
   becomes the relay's leg A and the tunnel's real agent is asked to connect
   a data connection (leg B). */
static void peer_open_stream(tm_conn *c) {
    tm_broker *b = c->b;
    tm_tunnel *tun = c->peer_tun;
    if (!tun || !tun->agent_online || !tun->agent || tun->agent->closing) {
        send_frame_raw(b, c->io, TM_MSG_DATA_BIND_ERROR, 0, "tunnel offline");
        conn_close(c, "tunnel offline");
        return;
    }
    long long pending = 0;
    for (tm_stream *st = tun->streams; st; st = st->next)
        if (!st->bound) pending++;
    if (pending >= b->cfg.max_pending_streams) {
        send_frame_raw(b, c->io, TM_MSG_DATA_BIND_ERROR, 0, "no capacity");
        conn_close(c, "no capacity");
        return;
    }

    size_t n = 0;
    uint8_t *lo = tm_frame_reader_drain(c->fr, &n);

    tm_stream *st = tm_stream_create_closed(b, tun, c->io,
                                            (uv_handle_t *)c->sock);
    if (!st) {
        free(lo);
        send_frame_raw(b, c->io, TM_MSG_DATA_BIND_ERROR, 0, "no capacity");
        conn_close(c, "no capacity");
        return;
    }
    c->sock = NULL;
    c->io = NULL;

    send_frame_raw(b, st->io_a, TM_MSG_DATA_BIND_OK, 0, NULL);
    tm_agent_send_frame(b, tun->agent,
                        tm_frame_make(TM_MSG_OPEN_STREAM, st->id, NULL, 0));
    if (n) { tm_stream_ingest_a(st, lo, n); free(lo); }
    tm_log_debug(b->log, "peer_stream_open", "stream_id", NULL,
                 "%u tunnel=%s", st->id, tun->id);

    tm_frame_reader_free(c->fr);
    c->fr = NULL;
    conn_unlink(c);
    uv_timer_stop(&c->hs_timer);
    uv_close((uv_handle_t *)&c->hs_timer, conn_free_cb);
}

static void peer_frame(tm_conn *c, tm_frame *f) {
    switch (f->type) {
    case TM_MSG_DATA_BIND:
        if (f->stream_id == 0) { peer_open_stream(c); return; }
        c->b->protocol_errors++;
        conn_close(c, "bad bind");
        return;
    case TM_MSG_CLOSE_STREAM: {
        tm_stream *st = tm_stream_find(c->b, c->peer_tun, f->stream_id);
        if (st) tm_stream_close(c->b, st);
        return;
    }
    case TM_MSG_PING:
        send_frame_raw(c->b, c->io, TM_MSG_PONG, 0, NULL);
        return;
    default:
        c->b->protocol_errors++;
        conn_close(c, "bad frame");
        return;
    }
}

/* ------------------------------------------------------------------ */
/* agent data connections (DATA_BIND as first frame)                   */
/* ------------------------------------------------------------------ */

static void data_conn_first_frame(tm_conn *c, tm_frame *f) {
    tm_broker *b = c->b;
    if (f->stream_id == 0 || f->payload_len == 0 ||
        f->payload_len > TM_MAX_SECRET) {
        b->protocol_errors++;
        conn_close(c, "bad bind");
        return;
    }
    tm_stream *st = NULL;
    for (tm_tunnel *t = b->tunnels; t && !st; t = t->next)
        st = tm_stream_find(b, t, f->stream_id);
    if (!st || st->bound || st->closing || !st->tun->enabled) {
        send_frame_raw(b, c->io, TM_MSG_DATA_BIND_ERROR, f->stream_id,
                       "no such stream");
        conn_close(c, "bad bind");
        return;
    }
    uint8_t hmac[32];
    char hex[65];
    tm_hmac_sha256(b->hmac_key, sizeof(b->hmac_key), f->payload,
                   f->payload_len, hmac);
    tm_sha256_hex(hmac, 32, hex);
    if (!tm_ct_eq_hex(hex, st->tun->agent_secret_hmac)) {
        b->failed_auths++;
        send_frame_raw(b, c->io, TM_MSG_DATA_BIND_ERROR, f->stream_id,
                       "bad credentials");
        conn_close(c, "bad bind");
        return;
    }

    size_t n = 0;
    uint8_t *lo = tm_frame_reader_drain(c->fr, &n);

    /* DATA_BIND_OK first: the agent frame-reads until it, then relays */
    send_frame_raw(b, c->io, TM_MSG_DATA_BIND_OK, f->stream_id, NULL);
    tm_stream_relay_attach_agent(b, st, c->io, (uv_handle_t *)c->sock);
    c->sock = NULL;
    c->io = NULL;
    if (n) { tm_stream_ingest(st, lo, n); free(lo); }
    tm_log_debug(b->log, "data_conn_bound", "stream_id", NULL,
                 "%u tunnel=%s", st->id, st->tun->id);

    tm_frame_reader_free(c->fr);
    c->fr = NULL;
    conn_unlink(c);
    uv_timer_stop(&c->hs_timer);
    uv_close((uv_handle_t *)&c->hs_timer, conn_free_cb);
}

/* ------------------------------------------------------------------ */
/* pre-promotion conn dispatch                                         */
/* ------------------------------------------------------------------ */

static void conn_frame(tm_conn *c, tm_frame *f) {
    if (!c->got_hello) {
        if (f->type == TM_MSG_HELLO) {
            c->got_hello = true;
            send_frame_raw(c->b, c->io, TM_MSG_HELLO_ACK, 0, NULL);
            return;
        }
        if (f->type == TM_MSG_DATA_BIND) {
            data_conn_first_frame(c, f);
            return;
        }
        c->b->protocol_errors++;
        conn_close(c, "bad first frame");
        return;
    }
    if (c->peer_authed) { peer_frame(c, f); return; }
    switch (f->type) {
    case TM_MSG_REGISTER:
        agent_register(c, f);
        return;
    case TM_MSG_AUTH:
        peer_auth(c, f);
        return;
    case TM_MSG_PING:
        send_frame_raw(c->b, c->io, TM_MSG_PONG, 0, NULL);
        return;
    default:
        c->b->protocol_errors++;
        conn_close(c, "bad control frame");
        return;
    }
}

static void conn_read(tm_io *io, const uint8_t *data, size_t len, void *arg) {
    tm_conn *c = (tm_conn *)arg;
    (void)io;
    c->last_rx_ms = tm_now_ms();
    bool err = false;
    tm_frame *f = tm_frame_reader_feed(c->fr, data, len, &err);
    if (err) { c->b->protocol_errors++; conn_close(c, "malformed frame"); return; }
    while (f) {
        conn_frame(c, f);
        tm_frame_free(f);
        /* Role promotion transfers the frame reader to an agent/stream and
           clears c->fr. Do not continue parsing through the old owner. */
        if (c->closing || !c->fr) return;
        f = tm_frame_reader_feed(c->fr, NULL, 0, &err);
        if (err) { c->b->protocol_errors++; conn_close(c, "malformed frame"); return; }
    }
}

static void conn_eof(tm_io *io, void *arg) {
    (void)io;
    tm_conn *c = (tm_conn *)arg;
    conn_close(c, "eof");
}

static void conn_error(tm_io *io, int err, void *arg) {
    (void)io; (void)err;
    tm_conn *c = (tm_conn *)arg;
    conn_close(c, "connection error");
}

static void conn_ready(tm_io *io, void *arg) {
    (void)io;
    tm_conn *c = (tm_conn *)arg;
    uv_timer_stop(&c->hs_timer);
    tm_log_debug(c->b->log, "conn_tls_ready", "remote", NULL, "%s", c->remote);
}

static void conn_hs_timeout(uv_timer_t *t) {
    tm_conn *c = (tm_conn *)t->data;
    if (c && !c->closing) conn_close(c, "handshake timeout");
}

static void conn_close(tm_conn *c, const char *why) {
    if (c->closing) return;
    c->closing = true;
    conn_unlink(c);
    uv_timer_stop(&c->hs_timer);
    uv_close((uv_handle_t *)&c->hs_timer, conn_free_cb);
    if (c->io) { tm_io_close(c->io); c->io = NULL; }
    else if (c->ssl) { SSL_free(c->ssl); }
    c->ssl = NULL;
    if (c->sock && !uv_is_closing((uv_handle_t *)c->sock))
        uv_close((uv_handle_t *)c->sock, tm_broker_tls_free_handle_cb);
    c->sock = NULL;
    if (c->fr) { tm_frame_reader_free(c->fr); c->fr = NULL; }
    tm_log_debug(c->b->log, "conn_closed", "remote", NULL,
                 "%s why=%s", c->remote, why);
    /* c is freed by conn_free_cb once the timer close completes */
}

/* ------------------------------------------------------------------ */
/* listener + sweep                                                    */
/* ------------------------------------------------------------------ */

static void on_control_accept(uv_stream_t *server, int status) {
    tm_broker *b = (tm_broker *)server->data;
    if (status != 0) return;
    if (b->shutting_down) return;

    uv_tcp_t *sock = tm_xcalloc(1, sizeof(*sock));
    uv_tcp_init(b->loop, sock);
    tm_tcp_tune(sock);
    if (uv_accept(server, (uv_stream_t *)sock) != 0) {
        uv_close((uv_handle_t *)sock, tm_broker_tls_free_handle_cb);
        return;
    }

    long long nconns = 0;
    for (tm_conn *x = b->conns; x; x = x->next) nconns++;
    if (nconns >= TM_MAX_PENDING_CONNS) {
        uv_close((uv_handle_t *)sock, tm_broker_tls_free_handle_cb);
        return;
    }

    tm_conn *c = tm_xcalloc(1, sizeof(*c));
    c->b = b;
    c->sock = sock;
    c->last_rx_ms = tm_now_ms();

    struct sockaddr_storage peer;
    int alen = sizeof(peer);
    if (uv_tcp_getpeername(sock, (struct sockaddr *)&peer, &alen) == 0)
        snprintf(c->remote, sizeof(c->remote), "%s",
                 tm_addr_str((struct sockaddr *)&peer));

    c->ssl = tm_broker_accept_ssl(b, true);
    if (!c->ssl) { conn_close(c, "ssl_new"); return; }

    uv_timer_init(b->loop, &c->hs_timer);
    c->hs_timer.data = c;
    uv_timer_start(&c->hs_timer, conn_hs_timeout,
                   (uint64_t)b->cfg.handshake_timeout_ms, 0);

    c->fr = tm_frame_reader_new();
    c->io = tm_io_ssl_new(b->loop, (uv_stream_t *)sock, c->ssl, true, true,
                          &(tm_io_cbs){
                              .ready_cb = conn_ready,
                              .read_cb = conn_read,
                              .eof_cb = conn_eof,
                              .error_cb = conn_error,
                              .arg = c,
                          });
    tm_io_start(c->io);
    tm_io_handshake(c->io);

    c->next = b->conns;
    b->conns = c;
    b->conns_total++;
}

void tm_control_listener_start(tm_broker *b) {
    uv_tcp_init(b->loop, &b->control_listener);
    b->control_listener.data = b;
    struct sockaddr_storage sa;
    if (tm_addr_parse(b->cfg.listen_host, b->cfg.control_port, &sa) != TM_OK) {
        tm_log_error(b->log, "bad_control_host", NULL, NULL, "%s",
                     b->cfg.listen_host);
        return;
    }
    int r = uv_tcp_bind(&b->control_listener, (const struct sockaddr *)&sa, 0);
    if (r != 0) {
        tm_log_error(b->log, "bind_control_failed", NULL, NULL,
                     "%s port=%u (%s)", b->cfg.listen_host,
                     (unsigned)b->cfg.control_port, uv_strerror(r));
        return;
    }
    if (uv_listen((uv_stream_t *)&b->control_listener, 256,
                  on_control_accept) != 0) {
        tm_log_error(b->log, "listen_control_failed", NULL, NULL,
                     "%s port=%u", b->cfg.listen_host,
                     (unsigned)b->cfg.control_port);
        return;
    }
    b->control_listening = true;

    uv_timer_init(b->loop, &b->control_tick);
    b->control_tick.data = b;
    uint64_t interval = (uint64_t)b->cfg.heartbeat_interval_ms / 2;
    if (interval < 500) interval = 500;
    uv_timer_start(&b->control_tick, control_tick_cb, interval, interval);
    tm_log_info(b->log, "control_listening", NULL, NULL, "port=%u",
                (unsigned)b->cfg.control_port);
}

void tm_agent_tick(tm_broker *b) {
    uint64_t now = tm_now_ms();
    for (tm_tunnel *tun = b->tunnels; tun; tun = tun->next) {
        tm_agent *a = tun->agent;
        if (!a || a->closing) continue;
        if (now - a->last_rx_ms > (uint64_t)b->cfg.idle_timeout_ms) {
            tm_log_warn(b->log, "agent_idle_timeout", "tunnel_id", NULL,
                        "%s", tun->id);
            tm_agent_drop(b, a, "idle timeout");
            continue;
        }
        if (now - a->last_ping_ms >= (uint64_t)b->cfg.heartbeat_interval_ms) {
            a->last_ping_ms = now;
            tm_agent_send_frame(b, a, tm_frame_make(TM_MSG_PING, 0, NULL, 0));
        }
    }
    tm_conn *c = b->conns;
    while (c) {
        tm_conn *nxt = c->next;
        if (!c->closing && now - c->last_rx_ms >
                              (uint64_t)b->cfg.idle_timeout_ms)
            conn_close(c, "idle timeout");
        c = nxt;
    }
}

static void control_tick_cb(uv_timer_t *t) {
    tm_broker *b = (tm_broker *)t->data;
    tm_agent_tick(b);
}

void tm_control_goaway_all(tm_broker *b) {
    for (tm_tunnel *tun = b->tunnels; tun; tun = tun->next) {
        if (tun->agent && !tun->agent->closing)
            tm_agent_send_frame(b, tun->agent,
                                tm_frame_make(TM_MSG_GOING_AWAY, 0, NULL, 0));
    }
}

void tm_control_close_all(tm_broker *b) {
    for (tm_tunnel *tun = b->tunnels; tun; tun = tun->next) {
        if (tun->agent) tm_agent_drop(b, tun->agent, "shutdown");
    }
    while (b->conns) conn_close(b->conns, "shutdown");
}

/* ------------------------------------------------------------------ */
/* tls helpers                                                         */
/* ------------------------------------------------------------------ */

SSL *tm_broker_accept_ssl(tm_broker *b, bool tls13) {
    SSL *ssl = SSL_new(b->tls_ctx);
    if (!ssl) return NULL;
    if (!tls13) {
        SSL_set_min_proto_version(ssl, TLS1_2_VERSION);
        SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
    }
    return ssl;
}
