#include "broker.h"
#include "tunnelmate/crypto.h"
#include "tunnelmate/net.h"
#include "tunnelmate/tls.h"
#include <openssl/err.h>

/* UDP plane: one public DTLS socket per tunnel. The broker demultiplexes
   datagrams on the tunnel socket by peer address into per-peer DTLS
   sessions. Raw envelopes (first byte 0x00) on open tunnels belong to
   public clients. Sessions authenticate with an AUTH_REQ envelope carrying
   the agent secret (becomes the agent session) or the shared token (peer
   session). All flow ids in the agent direction are broker-assigned;
   peer-side flow ids are session-scoped and translated. */

#define TM_ENV_HDR_LEN 11u
#define TM_DTLS_BUF 65536u

typedef struct {
    uv_udp_send_t req;
    uint8_t *buf;
    tm_udp_session *s;
} tm_udp_send;

static void pump_out(tm_udp_session *s);
static void pump_in(tm_udp_session *s);
static void session_maybe_free(tm_udp_session *s);

static void send_done(uv_udp_send_t *req, int status) {
    tm_udp_send *wr = (tm_udp_send *)req;
    (void)status;
    free(wr->buf);
    tm_udp_session *s = wr->s;
    free(wr);
    if (s) {
        s->inflight = false;
        if (s->closing) session_maybe_free(s);
        else pump_out(s);
    }
}

/* send an encrypted DTLS record (or raw envelope) from the tunnel socket */
static void udp_send_raw(tm_udp_session *s, tm_tunnel *tun,
                         const struct sockaddr *dst, const uint8_t *buf, size_t len) {
    tm_udp_send *wr = tm_xcalloc(1, sizeof(*wr));
    wr->buf = tm_xmalloc(len);
    memcpy(wr->buf, buf, len);
    wr->s = s;
    uv_buf_t b = uv_buf_init((char *)wr->buf, (unsigned)len);
    uv_udp_send(&wr->req, &tun->udp_sock, &b, 1, dst, send_done);
}

/* ------------------------------------------------------------------ */
/* session helpers                                                     */
/* ------------------------------------------------------------------ */

/* queue plaintext (envelope bytes) to be encrypted and sent */
static void session_queue(tm_udp_session *s, const uint8_t *data, size_t len) {
    if (s->closing) return;
    size_t queued = s->outq_len - s->outq_off;
    size_t max_bytes = (size_t)s->b->cfg.udp_queue_packets *
                       ((size_t)s->b->cfg.udp_max_datagram_size + 15u);
    if (s->outq_packets >= (size_t)s->b->cfg.udp_queue_packets ||
        len > UINT32_MAX || queued + 4u + len > max_bytes) {
        s->b->udp_dropped_queue_full++;
        return;
    }
    if (s->outq_len + 4u + len > s->outq_cap) {
        size_t ncap = s->outq_cap ? s->outq_cap * 2 : 4096;
        while (ncap < s->outq_len + 4u + len) ncap *= 2;
        if (s->outq_off) {
            memmove(s->outq, s->outq + s->outq_off, s->outq_len - s->outq_off);
            s->outq_len -= s->outq_off;
            s->outq_off = 0;
        }
        s->outq = tm_xrealloc(s->outq, ncap);
        s->outq_cap = ncap;
    }
    wr_u32(s->outq + s->outq_len, (uint32_t)len);
    memcpy(s->outq + s->outq_len + 4u, data, len);
    s->outq_len += 4u + len;
    s->outq_packets++;
    pump_out(s);
}

/* encrypt queued plaintext and emit DTLS records to the peer */
static void pump_out(tm_udp_session *s) {
    if (s->closing || s->inflight) return;
    while (s->outq_off < s->outq_len) {
        if (s->outq_len - s->outq_off < 4u) return;
        uint32_t plen = rd_u32(s->outq + s->outq_off);
        if ((size_t)plen > s->outq_len - s->outq_off - 4u) return;
        int w = SSL_write(s->ssl, s->outq + s->outq_off + 4u, (int)plen);
        if (w <= 0) {
            int e = SSL_get_error(s->ssl, w);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) break;
            return;
        }
        if ((uint32_t)w != plen) return;
        s->outq_off += 4u + plen;
        if (s->outq_packets) s->outq_packets--;
        break; /* exactly one DTLS application record per envelope */
    }
    if (s->outq_off == s->outq_len) { s->outq_len = 0; s->outq_off = 0; }
    uint8_t chunk[TM_DTLS_BUF];
    int n = BIO_read(s->wbio, chunk, sizeof(chunk));
    if (n <= 0) return;
    udp_send_raw(s, s->tun, (const struct sockaddr *)&s->peer, chunk, (size_t)n);
    s->inflight = true;
    s->pkts_tx++;
    s->tun->datagrams_tx++;
    s->tun->b->datagrams_tx_total++;
}

/* session timer: DTLS retransmit (handshake) + periodic idle sweep */
static void session_timer_cb(uv_timer_t *t) {
    tm_udp_session *s = (tm_udp_session *)t->data;
    if (!s || s->closing) return;
    tm_broker *b = s->b;
    uint64_t now = tm_now_ms();
    if (now - s->last_rx_ms > (uint64_t)b->cfg.udp_flow_idle_timeout_ms * 2) {
        tm_udp_session_close(b, s);
        return;
    }
    if (!s->handshake_done) {
        DTLSv1_handle_timeout(s->ssl);
        pump_out(s);
        struct timeval tv;
        uint64_t ms = 500;
        if (DTLSv1_get_timeout(s->ssl, &tv) == 1) {
            ms = (uint64_t)tv.tv_sec * 1000u + (uint64_t)(tv.tv_usec / 1000u);
            if (ms == 0) ms = 1;
        }
        uv_timer_start(&s->timer, session_timer_cb, ms, 0);
        return;
    }
    uv_timer_start(&s->timer, session_timer_cb, 30000, 0);
}

/* ------------------------------------------------------------------ */
/* flow table                                                          */
/* ------------------------------------------------------------------ */

static tm_udp_flow *flow_find(tm_tunnel *tun, uint64_t flow_id) {
    for (tm_udp_flow *f = tun->udp_flows; f; f = f->next)
        if (f->flow_id == flow_id) return f;
    return NULL;
}

static tm_udp_flow *flow_find_peer(tm_udp_session *s, uint64_t src_flow_id) {
    for (tm_udp_flow *f = s->tun->udp_flows; f; f = f->next)
        if (f->from_peer_session && f->peer_session == s &&
            f->src_flow_id == src_flow_id)
            return f;
    return NULL;
}

static tm_udp_flow *flow_find_src(tm_tunnel *tun, const struct sockaddr *addr) {
    for (tm_udp_flow *f = tun->udp_flows; f; f = f->next)
        if (!f->from_peer_session && tm_addr_eq((const struct sockaddr *)&f->src, addr))
            return f;
    return NULL;
}

static void flow_unlink(tm_tunnel *tun, tm_udp_flow *f) {
    tm_udp_flow **pp = &tun->udp_flows;
    while (*pp) {
        if (*pp == f) { *pp = f->next; break; }
        pp = &(*pp)->next;
    }
}

static void flow_free_cb(uv_handle_t *h) {
    free(h->data);
}

void tm_udp_flow_expire(tm_broker *b, tm_udp_flow *f) {
    if (!f) return;
    tm_tunnel *tun = f->tun;
    if (f->idle_timer.data) {
        uv_timer_stop(&f->idle_timer);
        if (!uv_is_closing((uv_handle_t *)&f->idle_timer))
            uv_close((uv_handle_t *)&f->idle_timer, flow_free_cb);
    }
    flow_unlink(tun, f);
    b->udp_flow_expired++;
}

static void flow_idle_cb(uv_timer_t *t) {
    tm_udp_flow *f = (tm_udp_flow *)t->data;
    if (f) tm_udp_flow_expire(f->b, f);
}

static bool rate_check(long long limit, uint64_t now,
                       long long *win_start, long long *win_count) {
    if (limit <= 0) return true;
    if (now - (uint64_t)*win_start >= 1000) { *win_start = (long long)now; *win_count = 0; }
    if (*win_count >= limit) return false;
    (*win_count)++;
    return true;
}

static size_t flow_count(tm_tunnel *tun) {
    size_t n = 0;
    for (tm_udp_flow *f = tun->udp_flows; f; f = f->next) n++;
    return n;
}

static tm_udp_flow *flow_new(tm_broker *b, tm_tunnel *tun,
                             bool from_peer_session, tm_udp_session *ps,
                             uint64_t src_flow_id,
                             const struct sockaddr_storage *src) {
    if (tun->next_flow_id == 0) tun->next_flow_id = 1;
    uint64_t fid = tun->next_flow_id++;
    tm_udp_flow *f = tm_xcalloc(1, sizeof(*f));
    f->flow_id = fid;
    f->src_flow_id = src_flow_id;
    f->tun = tun;
    f->from_peer_session = from_peer_session;
    f->peer_session = ps;
    if (src) f->src = *src;
    f->last_seen_ms = tm_now_ms();
    f->b = b;
    uv_timer_init(b->loop, &f->idle_timer);
    f->idle_timer.data = f;
    uv_timer_start(&f->idle_timer, flow_idle_cb,
                   (uint64_t)b->cfg.udp_flow_idle_timeout_ms, 0);
    f->next = tun->udp_flows;
    tun->udp_flows = f;
    b->flows_total++;
    return f;
}

static bool tunnel_pkt_limit(tm_broker *b, tm_tunnel *tun) {
    return rate_check(b->cfg.udp_max_packets_per_tunnel, tm_now_ms(),
                      &tun->udp_pkt_win_start, &tun->udp_pkt_win_count);
}

/* ------------------------------------------------------------------ */
/* session close / create                                              */
/* ------------------------------------------------------------------ */

static void session_maybe_free(tm_udp_session *s) {
    if (!s->closing || s->inflight || !s->timer_closed) return;
    if (s->ssl) SSL_free(s->ssl);
    BIO_free(s->rbio);
    BIO_free(s->wbio);
    free(s->outq);
    free(s);
}

static void session_timer_closed(uv_handle_t *h) {
    tm_udp_session *s = (tm_udp_session *)h->data;
    s->timer_closed = true;
    session_maybe_free(s);
}

void tm_udp_session_close(tm_broker *b, tm_udp_session *s) {
    if (!s || s->closing) return;
    s->closing = true;
    tm_tunnel *tun = s->tun;
    if (tun) {
        tm_udp_flow *f = tun->udp_flows;
        while (f) {
            tm_udp_flow *nxt = f->next;
            if (f->peer_session == s) tm_udp_flow_expire(b, f);
            f = nxt;
        }
        tm_udp_session **pp = &tun->udp_sessions;
        while (*pp) {
            if (*pp == s) { *pp = s->next; break; }
            pp = &(*pp)->next;
        }
        if (tun->agent_session == s) tun->agent_session = NULL;
        s->tun = NULL;
    }
    uv_timer_stop(&s->timer);
    if (!uv_is_closing((uv_handle_t *)&s->timer))
        uv_close((uv_handle_t *)&s->timer, session_timer_closed);
}

/* create a DTLS server session for a new peer address */
static tm_udp_session *session_create(tm_broker *b, tm_tunnel *tun,
                                      const struct sockaddr_storage *peer) {
    tm_udp_session *s = tm_xcalloc(1, sizeof(*s));
    s->tun = tun;
    s->b = b;
    s->peer = *peer;
    s->last_rx_ms = tm_now_ms();
    s->ssl = SSL_new(b->dtls_ctx);
    if (!s->ssl) { free(s); return NULL; }
    if (tm_dtls_attach_bio_pair(s->ssl, &s->rbio, &s->wbio) != TM_OK) {
        SSL_free(s->ssl);
        free(s);
        return NULL;
    }
    SSL_set_accept_state(s->ssl);
    uv_timer_init(b->loop, &s->timer);
    s->timer.data = s;
    uv_timer_start(&s->timer, session_timer_cb, 500, 0);
    s->next = tun->udp_sessions;
    tun->udp_sessions = s;
    return s;
}

/* ------------------------------------------------------------------ */
/* inbound path                                                        */
/* ------------------------------------------------------------------ */

/* forward payload to the agent's session (open flow) */
static void forward_to_agent(tm_broker *b, tm_tunnel *tun, uint64_t flow_id,
                             const uint8_t *payload, uint32_t plen) {
    if (!tun->agent_session || !tun->agent_session->authenticated) {
        b->udp_dropped_no_flow++;
        return;
    }
    if (plen > (uint32_t)b->cfg.udp_max_datagram_size) {
        b->udp_dropped_oversize++;
        return;
    }
    size_t elen;
    uint8_t *env = tm_env_encode(flow_id, 0, payload, plen, &elen);
    session_queue(tun->agent_session, env, elen);
    free(env);
}

/* forward payload to a peer/client (reply direction) */
static void forward_to_peer(tm_broker *b, tm_tunnel *tun, tm_udp_flow *f,
                            const uint8_t *payload, uint32_t plen) {
    if (plen > (uint32_t)b->cfg.udp_max_datagram_size) {
        b->udp_dropped_oversize++;
        return;
    }
    if (f->from_peer_session) {
        if (!f->peer_session || f->peer_session->closing) return;
        size_t elen;
        uint8_t *env = tm_env_encode(f->src_flow_id, 0, payload, plen, &elen);
        session_queue(f->peer_session, env, elen);
        free(env);
    } else {
        /* Open clients speak ordinary UDP; proprietary metadata never
           changes the application datagram. */
        udp_send_raw(NULL, tun, (const struct sockaddr *)&f->src, payload, plen);
        tun->datagrams_tx++;
        b->datagrams_tx_total++;
    }
}

/* handle an envelope arriving on the agent session */
static void agent_session_env(tm_udp_session *s, uint64_t flow_id, uint8_t flags,
                              const uint8_t *payload, uint32_t plen) {
    tm_broker *b = s->b;
    tm_tunnel *tun = s->tun;
    (void)flags;
    if (flow_id == 0) return; /* keepalive */
    tm_udp_flow *f = flow_find(tun, flow_id);
    if (!f) {
        b->udp_dropped_no_flow++;
        return;
    }
    f->last_seen_ms = tm_now_ms();
    f->pkts_rx++;
    f->bytes_rx += plen;
    tun->datagrams_rx++;
    b->datagrams_rx_total++;
    forward_to_peer(b, tun, f, payload, plen);
}

/* handle an envelope arriving on a peer session (closed tunnels) */
static void peer_session_env(tm_udp_session *s, uint64_t flow_id, uint8_t flags,
                             const uint8_t *payload, uint32_t plen) {
    tm_broker *b = s->b;
    tm_tunnel *tun = s->tun;
    if (!rate_check(b->cfg.udp_max_packets_per_source, tm_now_ms(),
                    &s->pkt_win_start, &s->pkt_win_count)) {
        b->udp_dropped_rate_limit++;
        return;
    }
    if (!tunnel_pkt_limit(b, tun)) {
        b->udp_dropped_rate_limit++;
        return;
    }
    (void)flags;
    if (flow_id == 0) return; /* keepalive */
    tm_udp_flow *f = flow_find_peer(s, flow_id);
    if (!f) {
        if (!rate_check(b->cfg.udp_flow_creation_rate, tm_now_ms(),
                        &tun->udp_flow_created_win_start,
                        &tun->udp_flow_created_win_count) ||
            flow_count(tun) >= (size_t)b->cfg.udp_max_flows_per_tunnel) {
            b->udp_dropped_rate_limit++;
            return;
        }
        f = flow_new(b, tun, true, s, flow_id, NULL);
    }
    f->last_seen_ms = tm_now_ms();
    f->pkts_rx++;
    f->bytes_rx += plen;
    tun->datagrams_rx++;
    b->datagrams_rx_total++;
    forward_to_agent(b, tun, f->flow_id, payload, plen);
}

/* handle an envelope arriving as a raw datagram (open tunnel client) */
static void open_client_datagram(tm_broker *b, tm_tunnel *tun,
                                 const struct sockaddr *addr,
                                 const uint8_t *payload, uint32_t plen) {
    if (!tunnel_pkt_limit(b, tun)) {
        b->udp_dropped_rate_limit++;
        return;
    }
    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof(peer));
    size_t addrlen = addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                 : sizeof(struct sockaddr_in);
    memcpy(&peer, addr, addrlen);
    tm_udp_flow *f = flow_find_src(tun, addr);
    if (!f) {
        if (!rate_check(b->cfg.udp_flow_creation_rate, tm_now_ms(),
                        &tun->udp_flow_created_win_start,
                        &tun->udp_flow_created_win_count) ||
            flow_count(tun) >= (size_t)b->cfg.udp_max_flows_per_tunnel) {
            b->udp_dropped_rate_limit++;
            return;
        }
        f = flow_new(b, tun, false, NULL, 0, &peer);
    }
    f->last_seen_ms = tm_now_ms();
    f->pkts_rx++;
    f->bytes_rx += plen;
    tun->datagrams_rx++;
    b->datagrams_rx_total++;
    forward_to_agent(b, tun, f->flow_id, payload, plen);
}

static bool looks_like_dtls(const uint8_t *data, size_t len) {
    if (len < 13u) return false;
    /* DTLS record content type and the DTLS 1.0/1.2 wire version family. */
    return data[0] >= 20u && data[0] <= 23u && data[1] == 0xfe &&
           (data[2] == 0xff || data[2] == 0xfd || data[2] == 0xfc);
}

/* process decrypted app data on a session (auth or relay) */
static void session_appdata(tm_udp_session *s, const uint8_t *data, size_t len) {
    tm_broker *b = s->b;
    tm_tunnel *tun = s->tun;
    if (!s->authenticated) {
        /* first message must be an AUTH_REQ envelope */
        if (len < TM_ENV_HDR_LEN || data[0] != 0x00) {
            b->failed_auths++;
            return;
        }
        uint64_t flow_id; uint8_t flags;
        const uint8_t *payload; uint32_t plen;
        if (tm_env_decode(data, len, &flow_id, &flags, &payload, &plen) != TM_OK ||
            !(flags & TM_ENV_FLAG_AUTH_REQ) || plen == 0 || plen > TM_MAX_SECRET) {
            b->failed_auths++;
            return;
        }
        uint8_t hmac[32];
        char hex[65];
        tm_hmac_sha256(b->hmac_key, sizeof(b->hmac_key), payload, plen, hmac);
        tm_sha256_hex(hmac, 32, hex);
        bool is_agent = tm_ct_eq_hex(hex, tun->agent_secret_hmac);
        bool is_peer = (!is_agent && tun->closed && tun->shared_token_hmac[0] &&
                        tm_ct_eq_hex(hex, tun->shared_token_hmac));
        if (!is_agent && !is_peer) {
            b->failed_auths++;
            tm_log_warn(b->log, "udp_auth_failed", "tunnel_id", NULL, "%s", tun->id);
            size_t elen;
            uint8_t *env = tm_env_encode(0, TM_ENV_FLAG_AUTH_ERR, NULL, 0, &elen);
            session_queue(s, env, elen);
            free(env);
            return;
        }
        s->authenticated = true;
        s->is_agent = is_agent;
        if (is_agent) {
            if (tun->agent_session && tun->agent_session != s)
                tm_udp_session_close(b, tun->agent_session);
            tun->agent_session = s;
        }
        tm_log_info(b->log, "udp_session_authed", "tunnel_id", NULL,
                    "%s role=%s", tun->id, is_agent ? "agent" : "peer");
        size_t elen;
        uint8_t *env = tm_env_encode(0, TM_ENV_FLAG_AUTH_OK, NULL, 0, &elen);
        session_queue(s, env, elen);
        free(env);
        size_t off = TM_ENV_HDR_LEN + plen;
        if (off < len) session_appdata(s, data + off, len - off);
        return;
    }
    if (len < TM_ENV_HDR_LEN || data[0] != 0x00) {
        b->protocol_errors++;
        return;
    }
    uint64_t flow_id; uint8_t flags;
    const uint8_t *payload; uint32_t plen;
    if (tm_env_decode(data, len, &flow_id, &flags, &payload, &plen) != TM_OK) {
        b->protocol_errors++;
        return;
    }
    if (s->is_agent) agent_session_env(s, flow_id, flags, payload, plen);
    else peer_session_env(s, flow_id, flags, payload, plen);
}

/* pump decrypted app data out of SSL */
static void drain_ssl(tm_udp_session *s) {
    if (!s->handshake_done) return;
    uint8_t buf[TM_DTLS_BUF];
    for (;;) {
        int n = SSL_read(s->ssl, buf, sizeof(buf));
        if (n > 0) {
            session_appdata(s, buf, (size_t)n);
            continue;
        }
        int e = SSL_get_error(s->ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return;
        return;
    }
}

static void pump_in(tm_udp_session *s) {
    if (s->closing) return;
    if (!s->handshake_done) {
        int r = SSL_accept(s->ssl);
        if (r == 1 && SSL_is_init_finished(s->ssl)) {
            s->handshake_done = true;
        } else {
            int e = SSL_get_error(s->ssl, r);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                pump_out(s);
                return;
            }
            unsigned long oe = ERR_get_error();
            char detail[160];
            ERR_error_string_n(oe, detail, sizeof(detail));
            tm_log_warn(s->b->log, "udp_dtls_handshake_failed", "tunnel_id", NULL,
                        "%s ssl_error=%d openssl=%s", s->tun->id, e, detail);
            return; /* handshake failed */
        }
    }
    drain_ssl(s);
    pump_out(s);
}

/* tunnel socket recv: demux envelopes vs DTLS sessions */
static void on_udp_packet(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags) {
    (void)flags;
    tm_tunnel *tun = (tm_tunnel *)handle->data;
    tm_broker *b = tun->b;
    /* libuv reports "nothing more to read" as nread==0 with a NULL address.
       nread==0 with an address is a real, zero-length datagram, which is legal
       UDP and must be forwarded rather than dropped. */
    if (nread < 0 || (nread == 0 && addr == NULL)) { free(buf->base); return; }
    if (b->shutting_down || !tun->enabled) { free(buf->base); return; }

    const uint8_t *data = (const uint8_t *)buf->base;
    size_t len = (size_t)nread;

    if (!tun->closed && !looks_like_dtls(data, len)) {
        if (len > (size_t)b->cfg.udp_max_datagram_size) {
            b->udp_dropped_oversize++;
            free(buf->base);
            return;
        }
        open_client_datagram(b, tun, addr, data, (uint32_t)len);
        free(buf->base);
        return;
    }

    /* DTLS record: session lookup by peer addr */
    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof(peer));
    size_t addrlen = addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                 : sizeof(struct sockaddr_in);
    memcpy(&peer, addr, addrlen);
    tm_udp_session *s = NULL;
    for (tm_udp_session *c = tun->udp_sessions; c; c = c->next) {
        if (tm_addr_eq((const struct sockaddr *)&c->peer, addr)) { s = c; break; }
    }
    if (!s) {
        if (!rate_check(b->cfg.udp_flow_creation_rate, tm_now_ms(),
                        &tun->udp_flow_created_win_start,
                        &tun->udp_flow_created_win_count)) {
            b->udp_dropped_rate_limit++;
            free(buf->base);
            return;
        }
        s = session_create(b, tun, &peer);
        if (!s) { free(buf->base); return; }
        tm_log_debug(b->log, "udp_session_new", "tunnel_id", NULL, "%s", tun->id);
    }
    s->last_rx_ms = tm_now_ms();
    s->pkts_rx++;
    BIO_write(s->rbio, data, (int)len);
    pump_in(s);
    free(buf->base);
}

/* ------------------------------------------------------------------ */
/* start / stop                                                        */
/* ------------------------------------------------------------------ */

static void udp_alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)handle; (void)suggested;
    buf->base = tm_xmalloc(65536u);
    buf->len = 65536u;
}

void tm_udp_start(tm_broker *b, tm_tunnel *tun) {
    if (tun->proto != TM_PROTO_UDP || tun->udp_open) return;
    uv_udp_init(b->loop, &tun->udp_sock);
    tun->udp_sock.data = tun;
    struct sockaddr_storage sa;
    if (tm_addr_parse(b->cfg.listen_host, tun->public_port, &sa) != TM_OK) {
        tm_log_error(b->log, "bad_public_host", NULL, NULL, "%s", b->cfg.listen_host);
        return;
    }
    int r = uv_udp_bind(&tun->udp_sock, (const struct sockaddr *)&sa, 0);
    if (r != 0) {
        tm_log_error(b->log, "bind_udp_failed", "tunnel_id", NULL,
                     "%s port=%u", tun->id, (unsigned)tun->public_port);
        return;
    }
    if (uv_udp_recv_start(&tun->udp_sock, udp_alloc_cb, on_udp_packet) != 0) {
        tm_log_error(b->log, "recv_udp_failed", "tunnel_id", NULL,
                     "%s port=%u", tun->id, (unsigned)tun->public_port);
        return;
    }
    tun->udp_open = true;
    tm_log_info(b->log, "udp_listening", "tunnel_id", NULL,
                "%s port=%u", tun->id, (unsigned)tun->public_port);
}

/* See tm_tunnel_listener_stop in broker_tcp for the close_refs contract. */
static void tunnel_udp_closed(uv_handle_t *h) {
    tm_tunnel *tun = (tm_tunnel *)h->data;
    tun->close_refs--;
    if (tun->deleting && tun->close_refs == 0) free(tun);
}

void tm_udp_stop(tm_broker *b, tm_tunnel *tun) {
    if (tun->udp_open) {
        uv_udp_recv_stop(&tun->udp_sock);
        tun->close_refs++;
        uv_close((uv_handle_t *)&tun->udp_sock, tunnel_udp_closed);
        tun->udp_open = false;
    }
    while (tun->udp_sessions) tm_udp_session_close(b, tun->udp_sessions);
    while (tun->udp_flows) tm_udp_flow_expire(b, tun->udp_flows);
    tun->agent_session = NULL;
}
