#include "broker.h"
#include "tunnelmate/net.h"

/* Per-tunnel public TCP listener: accepts consumer connections, enforces a
   per-source-IP connection rate, and hands each accepted socket to a pending
   stream that awaits the agent's TLS data connection (OPEN_STREAM). */

typedef struct tm_accept_rate tm_accept_rate;

struct tm_accept_rate {
    struct sockaddr_storage ip;
    uint64_t win_start;
    long long count;
    tm_accept_rate *next;
};

static tm_accept_rate *rate_find(tm_broker *b, const struct sockaddr_storage *ip) {
    tm_accept_rate *r = b->accept_rates;
    while (r) {
        /* Keyed by address only: every inbound connection has a fresh source
           port, so including it would give each connection its own bucket and
           the limit would never apply. */
        if (tm_addr_eq_ip((const struct sockaddr *)&r->ip, (const struct sockaddr *)ip))
            return r;
        r = r->next;
    }
    r = tm_xcalloc(1, sizeof(*r));
    r->ip = *ip;
    r->win_start = tm_now_ms();
    r->next = b->accept_rates;
    b->accept_rates = r;
    return r;
}

static void rate_cleanup(tm_broker *b, uint64_t now) {
    tm_accept_rate **pp = &b->accept_rates;
    while (*pp) {
        tm_accept_rate *r = *pp;
        if (now - r->win_start > 60000 && r->count == 0) {
            *pp = r->next;
            free(r);
            continue;
        }
        pp = &(*pp)->next;
    }
}

static bool rate_allow(tm_broker *b, const struct sockaddr_storage *ip) {
    uint64_t now = tm_now_ms();
    tm_accept_rate *r = rate_find(b, ip);
    if (now - r->win_start >= 1000) {
        r->win_start = now;
        r->count = 0;
    }
    if (r->count >= b->cfg.connect_rate_per_ip) {
        b->conns_rate_limited++;
        return false;
    }
    r->count++;
    rate_cleanup(b, now);
    return true;
}

static void on_public_accept(uv_stream_t *server, int status) {
    tm_tunnel *tun = (tm_tunnel *)server->data;
    tm_broker *b = tun->b;
    if (status != 0) return;
    if (b->shutting_down || !tun->enabled) return;

    /* The connection must be accepted before its peer address can be read;
       a listening handle has no peer. Always drain the backlog entry, then
       decide whether to keep it. */
    uv_tcp_t *sock = tm_xcalloc(1, sizeof(*sock));
    uv_tcp_init(b->loop, sock);
    if (uv_accept(server, (uv_stream_t *)sock) != 0) {
        uv_close((uv_handle_t *)sock, tm_broker_tls_free_handle_cb);
        return;
    }

    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof(peer));
    int alen = (int)sizeof(peer);
    if (uv_tcp_getpeername(sock, (struct sockaddr *)&peer, &alen) != 0)
        memset(&peer, 0, sizeof(peer));

    if (!rate_allow(b, &peer)) {
        uv_close((uv_handle_t *)sock, tm_broker_tls_free_handle_cb);
        return;
    }

    if (!tun->agent_online) {
        tun->conns_rejected_offline++;
        uv_close((uv_handle_t *)sock, tm_broker_tls_free_handle_cb);
        return;
    }

    tm_stream *st = tm_stream_create_open(b, tun, sock);
    if (!st) {
        uv_close((uv_handle_t *)sock, tm_broker_tls_free_handle_cb);
        return;
    }
    memcpy(&st->peer_addr, &peer, sizeof(peer));

    if (tun->proto == TM_PROTO_UDP) {
        /* public TCP port only hosts TCP tunnels; reject mismatch */
        tm_stream_close(b, st);
        return;
    }

    /* notify the agent: OPEN_STREAM with the assigned stream id */
    tm_agent_send_frame(b, tun->agent,
                        tm_frame_make(TM_MSG_OPEN_STREAM, st->id, NULL, 0));
    tm_log_debug(b->log, "public_accept", "stream_id", NULL,
                 "%u tunnel=%s", st->id, tun->id);
}

void tm_tunnel_listener_start(tm_broker *b, tm_tunnel *tun) {
    if (tun->proto != TM_PROTO_TCP || tun->listener_open) return;
    /* Closed TCP tunnels are reached only through an authenticated peer on the
       control port. Binding a public listener for them would expose the private
       service to unauthenticated clients. */
    if (tun->closed) return;
    if (tun->deleting) return;
    if (tun->listener_closing) {
        /* Re-initialising a handle before its close callback runs corrupts the
           loop's handle list; retry once the close completes. */
        tun->listener_restart_pending = true;
        return;
    }
    uv_tcp_init(b->loop, &tun->listener);
    tun->listener.data = tun;
    struct sockaddr_storage sa;
    if (tm_addr_parse(b->cfg.listen_host, tun->public_port, &sa) != TM_OK) {
        tm_log_error(b->log, "bad_public_host", NULL, NULL, "%s", b->cfg.listen_host);
        return;
    }
    int r = uv_tcp_bind(&tun->listener, (const struct sockaddr *)&sa, 0);
    if (r != 0) {
        tm_log_error(b->log, "bind_public_failed", "tunnel_id", NULL,
                     "%s port=%u", tun->id, (unsigned)tun->public_port);
        return;
    }
    if (uv_listen((uv_stream_t *)&tun->listener, 128, on_public_accept) != 0) {
        tm_log_error(b->log, "listen_public_failed", "tunnel_id", NULL,
                     "%s port=%u", tun->id, (unsigned)tun->public_port);
        return;
    }
    tun->listener_open = true;
    tm_log_info(b->log, "public_listening", "tunnel_id", NULL,
                "%s port=%u", tun->id, (unsigned)tun->public_port);
}

/* close_refs counts uv_close() calls still in flight for this tunnel. It is
   incremented whenever a close is issued and decremented in the callback, so a
   close started before tm_tunnel_delete() cannot free the tunnel twice or
   underflow the count. */
static void tunnel_listener_closed(uv_handle_t *h) {
    tm_tunnel *tun = (tm_tunnel *)h->data;
    tun->listener_closing = false;
    tun->close_refs--;
    if (tun->deleting) {
        if (tun->close_refs == 0) free(tun);
        return;
    }
    if (tun->listener_restart_pending) {
        tun->listener_restart_pending = false;
        tm_tunnel_listener_start(tun->b, tun);
    }
}

void tm_tunnel_listener_stop(tm_broker *b, tm_tunnel *tun) {
    (void)b;
    tun->listener_restart_pending = false;
    if (tun->listener_open) {
        tun->close_refs++;
        tun->listener_closing = true;
        uv_close((uv_handle_t *)&tun->listener, tunnel_listener_closed);
        tun->listener_open = false;
    }
}
