#include "peer.h"
#include "tunnelmate/net.h"
#include "tunnelmate/tls.h"

/* UDP mode: one DTLS 1.2 client session to the broker's public UDP port.
   After handshake, send AUTH_REQ(shared_token); on AUTH_OK relay envelopes
   between the local UDP socket and the broker. Local source addresses are
   mapped to peer-chosen flow ids; the broker echoes them back. */

typedef struct {
    uv_udp_send_t req;
    uint8_t *buf;
} tm_psend;

static void send_done(uv_udp_send_t *req, int status) {
    (void)status;
    tm_psend *wr = (tm_psend *)req;
    free(wr->buf);
    free(wr);
}

static void udp_send_raw(tm_peer *p, const uint8_t *data, size_t len) {
    if (p->udp_closing) return;
    tm_psend *wr = tm_xcalloc(1, sizeof(*wr));
    wr->buf = tm_xmalloc(len);
    memcpy(wr->buf, data, len);
    uv_buf_t b = uv_buf_init((char *)wr->buf, (unsigned)len);
    uv_udp_send(&wr->req, &p->broker_udp, &b, 1, NULL, send_done);
}

static void pump_out(tm_peer *p);

/* queue plaintext (envelope bytes) for SSL_write, then flush wbio */
static void udp_queue(tm_peer *p, const uint8_t *data, size_t len) {
    if (p->udp_closing || !p->udp_ssl) return;
    size_t queued = p->udp_outq_len - p->udp_outq_off;
    size_t max_bytes = 256u * ((size_t)p->cfg.udp_max_datagram_size + 15u);
    if (p->udp_outq_packets >= 256u || len > UINT32_MAX ||
        queued + 4u + len > max_bytes) return;
    if (p->udp_outq_len + 4u + len > p->udp_outq_cap) {
        size_t ncap = p->udp_outq_cap ? p->udp_outq_cap * 2 : 4096;
        while (ncap < p->udp_outq_len + 4u + len) ncap *= 2;
        if (p->udp_outq_off) {
            memmove(p->udp_outq, p->udp_outq + p->udp_outq_off,
                    p->udp_outq_len - p->udp_outq_off);
            p->udp_outq_len -= p->udp_outq_off;
            p->udp_outq_off = 0;
        }
        p->udp_outq = tm_xrealloc(p->udp_outq, ncap);
        p->udp_outq_cap = ncap;
    }
    wr_u32(p->udp_outq + p->udp_outq_len, (uint32_t)len);
    memcpy(p->udp_outq + p->udp_outq_len + 4u, data, len);
    p->udp_outq_len += 4u + len;
    p->udp_outq_packets++;
    pump_out(p);
}

static void pump_out(tm_peer *p) {
    if (p->udp_closing || !p->udp_ssl) return;
    if (p->udp_outq_off < p->udp_outq_len) {
        if (p->udp_outq_len - p->udp_outq_off < 4u) return;
        uint32_t plen = rd_u32(p->udp_outq + p->udp_outq_off);
        if ((size_t)plen > p->udp_outq_len - p->udp_outq_off - 4u) return;
        int w = SSL_write(p->udp_ssl, p->udp_outq + p->udp_outq_off + 4u,
                          (int)plen);
        if (w <= 0) {
            int e = SSL_get_error(p->udp_ssl, w);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                return;
            tm_peer_udp_stop(p);
            return;
        }
        if ((uint32_t)w != plen) return;
        p->udp_outq_off += 4u + plen;
        if (p->udp_outq_packets) p->udp_outq_packets--;
        if (p->udp_outq_off == p->udp_outq_len) {
            p->udp_outq_len = 0;
            p->udp_outq_off = 0;
        }
    }
    uint8_t chunk[TM_DEFAULT_DATAGRAM + 1024u];
    for (;;) {
        int n = BIO_read(p->udp_wbio, chunk, sizeof(chunk));
        if (n <= 0) break;
        udp_send_raw(p, chunk, (size_t)n);
    }
    if (p->udp_outq_off < p->udp_outq_len) pump_out(p);
}

/* ---------------------- local flow table ---------------------------- */

static void flow_close(tm_peer *p, tm_pflow *f) {
    tm_pflow **pp = &p->udp_flows;
    while (*pp) {
        if (*pp == f) { *pp = f->next; break; }
        pp = &(*pp)->next;
    }
    free(f);
}

static tm_pflow *flow_find(tm_peer *p, uint64_t flow_id) {
    for (tm_pflow *f = p->udp_flows; f; f = f->next)
        if (f->flow_id == flow_id) return f;
    return NULL;
}

static tm_pflow *flow_find_src(tm_peer *p, const struct sockaddr *addr) {
    for (tm_pflow *f = p->udp_flows; f; f = f->next)
        if (tm_addr_eq((const struct sockaddr *)&f->src, addr)) return f;
    return NULL;
}

static uint64_t flow_id_new(tm_peer *p) {
    uint64_t id;
    do {
        id = p->next_flow_id++;
        if (id == 0) id = p->next_flow_id++;
    } while (flow_find(p, id));
    return id;
}

/* ---------------------- inbound paths ------------------------------- */

static void udp_alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)handle; (void)suggested;
    buf->base = tm_xmalloc(65536u);
    buf->len = 65536u;
}

/* local app -> broker */
static void local_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags) {
    (void)flags;
    tm_peer *p = (tm_peer *)handle->data;
    if (nread <= 0) { free(buf->base); return; }
    if (p->udp_closing || !p->udp_authed) { free(buf->base); return; }
    size_t plen = (size_t)nread;
    if (plen > (size_t)p->cfg.udp_max_datagram_size) { free(buf->base); return; }

    tm_pflow *f = flow_find_src(p, addr);
    if (!f) {
        long long nf = 0;
        for (tm_pflow *x = p->udp_flows; x; x = x->next) nf++;
        if (nf >= p->cfg.udp_max_flows) { free(buf->base); return; }
        f = tm_xcalloc(1, sizeof(*f));
        f->flow_id = flow_id_new(p);
        size_t addrlen = addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
                                                     : sizeof(struct sockaddr_in);
        memcpy(&f->src, addr, addrlen);
        f->last_seen_ms = tm_now_ms();
        f->p = p;
        f->next = p->udp_flows;
        p->udp_flows = f;
    }
    f->last_seen_ms = tm_now_ms();

    size_t elen;
    uint8_t *env = tm_env_encode(f->flow_id, 0, (const uint8_t *)buf->base,
                                 (uint32_t)plen, &elen);
    free(buf->base);
    udp_queue(p, env, elen);
    free(env);
}

/* broker -> local app */
static void handle_broker_env(tm_peer *p, uint64_t flow_id,
                              const uint8_t *payload, uint32_t plen) {
    if (flow_id == 0) return; /* keepalive */
    if (plen > (uint32_t)p->cfg.udp_max_datagram_size) return;
    tm_pflow *f = flow_find(p, flow_id);
    if (!f) return;
    f->last_seen_ms = tm_now_ms();
    uint8_t *copy = tm_xmalloc(plen);
    memcpy(copy, payload, plen);
    uv_buf_t b = uv_buf_init((char *)copy, (unsigned)plen);
    tm_psend *wr = tm_xcalloc(1, sizeof(*wr));
    wr->buf = copy;
    uv_udp_send(&wr->req, &p->local_udp, &b, 1, (const struct sockaddr *)&f->src,
                send_done);
}

static void flow_sweep_cb(uv_timer_t *t) {
    tm_peer *p = (tm_peer *)t->data;
    if (!p) return;
    uint64_t now = tm_now_ms();
    tm_pflow *f = p->udp_flows;
    while (f) {
        tm_pflow *nxt = f->next;
        if (now - f->last_seen_ms > (uint64_t)p->cfg.udp_flow_idle_timeout_ms)
            flow_close(p, f);
        f = nxt;
    }
}

static void keepalive_cb(uv_timer_t *t) {
    tm_peer *p = (tm_peer *)t->data;
    if (!p || p->udp_closing || !p->udp_authed) return;
    size_t elen;
    uint8_t *env = tm_env_encode(0, 0, NULL, 0, &elen);
    udp_queue(p, env, elen);
    free(env);
}

/* ---------------------- DTLS session -------------------------------- */

static void udp_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
    (void)addr; (void)flags;
    tm_peer *p = (tm_peer *)handle->data;
    if (nread <= 0) { free(buf->base); return; }
    if (p->udp_closing) { free(buf->base); return; }
    BIO_write(p->udp_rbio, buf->base, (int)nread);
    free(buf->base);

    if (!SSL_is_init_finished(p->udp_ssl)) {
        int r = SSL_connect(p->udp_ssl);
        int e = SSL_get_error(p->udp_ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            pump_out(p);
            return;
        }
        if (e != SSL_ERROR_NONE) {
            tm_log_warn(p->log, "udp_dtls_error", NULL, NULL,
                        "handshake failed (err=%d)", e);
            tm_peer_udp_stop(p);
            return;
        }
        if (SSL_is_init_finished(p->udp_ssl)) {
            size_t elen;
            uint8_t *env = tm_env_encode(0, TM_ENV_FLAG_AUTH_REQ,
                                         (const uint8_t *)p->cfg.token,
                                         (uint32_t)strlen(p->cfg.token), &elen);
            udp_queue(p, env, elen);
            free(env);
        }
        pump_out(p);
        return;
    }

    uint8_t d[TM_DEFAULT_DATAGRAM + 1024u];
    for (;;) {
        int n = SSL_read(p->udp_ssl, d, sizeof(d));
        if (n <= 0) {
            int e = SSL_get_error(p->udp_ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) break;
            break;
        }
        uint64_t flow_id;
        uint8_t eflags;
        const uint8_t *payload;
        uint32_t plen;
        if (tm_env_decode(d, (size_t)n, &flow_id, &eflags, &payload, &plen)
            != TM_OK) {
            continue;
        }
        if (eflags == TM_ENV_FLAG_AUTH_OK) {
            if (!p->udp_authed) {
                p->udp_authed = true;
                tm_log_info(p->log, "udp_authed", NULL, NULL, "tunnel=%s",
                            p->cfg.tunnel_id);
            }
            continue;
        }
        if (eflags == TM_ENV_FLAG_AUTH_ERR) {
            tm_log_error(p->log, "udp_auth_rejected", NULL, NULL,
                         "tunnel=%s", p->cfg.tunnel_id);
            tm_peer_udp_stop(p);
            return;
        }
        if (eflags == 0) handle_broker_env(p, flow_id, payload, plen);
    }
    pump_out(p);
}

static void udp_reconnect(uv_timer_t *t);

void tm_peer_udp_start(tm_peer *p) {
    if (p->udp_ssl) return;
    if (p->shutting_down) return;

    uv_udp_init(p->loop, &p->local_udp);
    p->local_udp.data = p;
    struct sockaddr_storage lsa;
    if (tm_addr_parse(p->cfg.listen_host, p->cfg.listen_port, &lsa) != TM_OK) {
        tm_log_error(p->log, "bad_listen_host", NULL, NULL, "%s",
                     p->cfg.listen_host);
        return;
    }
    if (uv_udp_bind(&p->local_udp, (const struct sockaddr *)&lsa, 0) != 0) {
        tm_log_error(p->log, "udp_bind_failed", NULL, NULL, "%s:%u",
                     p->cfg.listen_host, (unsigned)p->cfg.listen_port);
        uv_close((uv_handle_t *)&p->local_udp, NULL);
        return;
    }
    uv_udp_recv_start(&p->local_udp, udp_alloc_cb, local_recv_cb);

    uv_udp_init(p->loop, &p->broker_udp);
    p->broker_udp.data = p;

    struct sockaddr_storage sa;
    if (tm_addr_parse(p->cfg.broker_host, p->cfg.public_port, &sa) != TM_OK) {
        tm_log_error(p->log, "bad_broker_host", NULL, NULL, "%s",
                     p->cfg.broker_host);
        return;
    }
    if (uv_udp_connect(&p->broker_udp, (const struct sockaddr *)&sa) != 0) {
        uv_close((uv_handle_t *)&p->broker_udp, NULL);
        return;
    }

    p->udp_ssl = SSL_new(p->dtls_ctx);
    if (!p->udp_ssl) {
        uv_close((uv_handle_t *)&p->broker_udp, NULL);
        return;
    }
    if (tm_tls_configure_client_ssl(p->udp_ssl, p->cfg.broker_host,
                                    p->cfg.verify_ca) != TM_OK) {
        SSL_free(p->udp_ssl);
        p->udp_ssl = NULL;
        uv_close((uv_handle_t *)&p->broker_udp, NULL);
        return;
    }
    if (tm_dtls_attach_bio_pair(p->udp_ssl, &p->udp_rbio, &p->udp_wbio) != TM_OK) {
        SSL_free(p->udp_ssl);
        p->udp_ssl = NULL;
        uv_close((uv_handle_t *)&p->broker_udp, NULL);
        return;
    }
    SSL_set_connect_state(p->udp_ssl);
    uv_udp_recv_start(&p->broker_udp, udp_alloc_cb, udp_recv_cb);
    uv_timer_init(p->loop, &p->udp_flow_timer);
    p->udp_flow_timer.data = p;
    uv_timer_start(&p->udp_flow_timer, flow_sweep_cb, 15000, 15000);
    uv_timer_init(p->loop, &p->udp_timer);
    p->udp_timer.data = p;
    uv_timer_start(&p->udp_timer, keepalive_cb, 15000, 15000);
    p->udp_closing = false;
    SSL_connect(p->udp_ssl);
    pump_out(p);
    tm_log_info(p->log, "udp_started", NULL, NULL, "%s:%u",
                p->cfg.broker_host, (unsigned)p->cfg.public_port);
}

void tm_peer_udp_stop(tm_peer *p) {
    if (!p->udp_ssl && !p->udp_flows && !p->udp_outq) return;
    uv_udp_recv_stop(&p->broker_udp);
    if (!uv_is_closing((uv_handle_t *)&p->broker_udp))
        uv_close((uv_handle_t *)&p->broker_udp, NULL);
    uv_udp_recv_stop(&p->local_udp);
    if (!uv_is_closing((uv_handle_t *)&p->local_udp))
        uv_close((uv_handle_t *)&p->local_udp, NULL);
    uv_timer_stop(&p->udp_timer);
    uv_timer_stop(&p->udp_flow_timer);
    while (p->udp_flows) flow_close(p, p->udp_flows);
    if (p->udp_ssl) { SSL_free(p->udp_ssl); p->udp_ssl = NULL; }
    if (p->udp_rbio) { BIO_free(p->udp_rbio); p->udp_rbio = NULL; }
    if (p->udp_wbio) { BIO_free(p->udp_wbio); p->udp_wbio = NULL; }
    free(p->udp_outq);
    p->udp_outq = NULL;
    p->udp_outq_len = p->udp_outq_cap = p->udp_outq_off = 0;
    p->udp_outq_packets = 0;
    p->udp_authed = false;
    p->udp_closing = true;
    if (p->shutting_down) return;
    /* reconnect with jittered backoff */
    p->reconnect_delay_ms *= 2;
    if (p->reconnect_delay_ms > (uint64_t)p->cfg.reconnect_max_delay_ms)
        p->reconnect_delay_ms = (uint64_t)p->cfg.reconnect_max_delay_ms;
    long long jitter = (long long)p->reconnect_delay_ms / 5;
    uint64_t delay = p->reconnect_delay_ms +
                     (uint64_t)(tm_now_ms() % (uint64_t)(2 * jitter + 1) -
                                jitter);
    uv_timer_init(p->loop, &p->reconnect_timer);
    p->reconnect_timer.data = p;
    uv_timer_start(&p->reconnect_timer, udp_reconnect, delay, 0);
}

static void udp_reconnect(uv_timer_t *t) {
    tm_peer *p = (tm_peer *)t->data;
    if (p && !p->shutting_down) {
        uv_close((uv_handle_t *)&p->reconnect_timer, NULL);
        tm_peer_udp_start(p);
    }
}
