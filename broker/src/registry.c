#include "broker.h"
#include "tunnelmate/crypto.h"

tm_tunnel *tm_tunnel_find(tm_broker *b, const char *id) {
    for (tm_tunnel *t = b->tunnels; t; t = t->next) {
        if (strcmp(t->id, id) == 0) return t;
    }
    return NULL;
}

bool tm_port_in_range(tm_broker *b, uint16_t port) {
    return port >= b->cfg.public_port_start && port <= b->cfg.public_port_end;
}

static size_t port_index(tm_broker *b, uint16_t port) {
    return (size_t)(port - b->cfg.public_port_start);
}

uint16_t tm_port_alloc(tm_broker *b, tm_proto proto, uint16_t prefer) {
    bool *table = proto == TM_PROTO_TCP ? b->ports_tcp : b->ports_udp;
    size_t n = (size_t)(b->cfg.public_port_end - b->cfg.public_port_start) + 1;
    /* TCP and UDP have independent port namespaces. */
    if (b->ports_used >= (long long)(n * 2u)) return 0;
    if (prefer && tm_port_in_range(b, prefer) && !table[port_index(b, prefer)]) {
        table[port_index(b, prefer)] = true;
        b->ports_used++;
        return prefer;
    }
    /* round-robin from a rotating cursor */
    static size_t cursor = 0;
    size_t start = cursor;
    for (size_t i = 0; i < n; i++) {
        size_t idx = (start + i) % n;
        if (!table[idx]) {
            table[idx] = true;
            b->ports_used++;
            cursor = (idx + 1) % n;
            return (uint16_t)(b->cfg.public_port_start + idx);
        }
    }
    return 0;
}

void tm_port_free(tm_broker *b, tm_proto proto, uint16_t port) {
    if (!tm_port_in_range(b, port)) return;
    bool *table = proto == TM_PROTO_TCP ? b->ports_tcp : b->ports_udp;
    if (table[port_index(b, port)]) b->ports_used--;
    table[port_index(b, port)] = false;
}

tm_tunnel *tm_tunnel_create(tm_broker *b, const char *id, tm_proto proto,
                            bool closed, const char *agent_hmac,
                            const char *token_hmac, uint16_t prefer_port,
                            uint16_t *allocated) {
    if (b->shutting_down) return NULL;
    if (b->tunnel_count >= b->cfg.max_tunnels) return NULL;
    if (tm_tunnel_find(b, id)) return NULL;
    if (strlen(id) > TM_TUNNEL_ID_LEN) return NULL;
    /* A closed TCP tunnel has no public listener, so it must not consume a
       public port. Closed UDP still needs one: it is the DTLS endpoint the
       authenticated peer connects to. */
    bool needs_public_port = !(closed && proto == TM_PROTO_TCP);
    uint16_t port = 0;
    if (needs_public_port) {
        port = tm_port_alloc(b, proto, prefer_port);
        if (!port) return NULL;
    }

    tm_tunnel *t = tm_xcalloc(1, sizeof(*t));
    snprintf(t->id, sizeof(t->id), "%s", id);
    t->proto = proto;
    t->closed = closed;
    t->enabled = true;
    t->public_port = port;
    snprintf(t->agent_secret_hmac, sizeof(t->agent_secret_hmac), "%s", agent_hmac ? agent_hmac : "");
    if (token_hmac)
        snprintf(t->shared_token_hmac, sizeof(t->shared_token_hmac), "%s", token_hmac);
    t->created_at_ms = tm_now_ms();
    t->last_seen_ms = t->created_at_ms;
    t->next_flow_id = 1;
    t->b = b;

    t->next = b->tunnels;
    b->tunnels = t;
    b->tunnel_count++;

    if (proto == TM_PROTO_TCP) tm_tunnel_listener_start(b, t);
    else tm_udp_start(b, t);

    *allocated = port;
    return t;
}

/* close everything belonging to the tunnel (listeners, sessions, streams) */
void tm_tunnel_teardown(tm_broker *b, tm_tunnel *t) {
    if (t->proto == TM_PROTO_TCP) tm_tunnel_listener_stop(b, t);
    else tm_udp_stop(b, t);

    /* drop control agent */
    if (t->agent) tm_agent_drop(b, t->agent, "tunnel deleted");

    /* close all streams */
    tm_stream *st = t->streams;
    while (st) {
        tm_stream *nxt = st->next;
        tm_stream_close(b, st);
        st = nxt;
    }

    if (t->proto == TM_PROTO_TCP) tm_port_free(b, TM_PROTO_TCP, t->public_port);
    else tm_port_free(b, TM_PROTO_UDP, t->public_port);
}

static void tunnel_remove_from_list(tm_broker *b, tm_tunnel *t) {
    tm_tunnel **pp = &b->tunnels;
    while (*pp) {
        if (*pp == t) { *pp = t->next; break; }
        pp = &(*pp)->next;
    }
}

int tm_tunnel_delete(tm_broker *b, const char *id, char *err, size_t errlen) {
    tm_tunnel *t = tm_tunnel_find(b, id);
    if (!t) {
        snprintf(err, errlen, "tunnel not found");
        return -1;
    }
    t->deleting = true;
    tm_tunnel_teardown(b, t);
    tunnel_remove_from_list(b, t);
    b->tunnel_count--;
    if (t->close_refs == 0) free(t);
    return 0;
}
