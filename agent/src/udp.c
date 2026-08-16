#include "agent.h"
#include "tunnelmate/net.h"
#include "tunnelmate/crypto.h"

/* UDP data plane: one DTLS 1.2 client session to the broker's public port.
   After handshake, send AUTH_REQ(agent_secret); on AUTH_OK relay envelopes.
   Broker-assigned flow ids map to connected local UDP sockets; replies are
   tagged with the same flow id. */

typedef struct {
    uv_udp_send_t req;
    uint8_t *buf;
} tm_asend;

static void send_done(uv_udp_send_t *req, int status) {
    (void)status;
    tm_asend *wr = (tm_asend *)req;
    free(wr->buf);
    free(wr);
}

static void udp_send_raw(tm_agent_app *a, const uint8_t *data, size_t len) {
    if (a->udp_closing) return;
    tm_asend *wr = tm_xcalloc(1, sizeof(*wr));
    wr->buf = tm_xmalloc(len);
    memcpy(wr->buf, data, len);
    uv_buf_t b = uv_buf_init((char *)wr->buf, (unsigned)len);
    uv_udp_send(&wr->req, &a->udp_sock, &b, 1, NULL, send_done);
}

static void pump_out(tm_agent_app *a);

/* queue plaintext (envelope bytes) for SSL_write, then flush wbio */
static void udp_queue(tm_agent_app *a, const uint8_t *data, size_t len) {
    if (a->udp_closing || !a->udp_ssl) return;
    if (a->udp_outq_len + len > a->udp_outq_cap) {
        size_t ncap = a->udp_outq_cap ? a->udp_outq_cap * 2 : 4096;
        while (ncap < a->udp_outq_len + len) ncap *= 2;
        a->udp_outq = tm_xrealloc(a->udp_outq, ncap);
        a->udp_outq_cap = ncap;
    }
    memcpy(a->udp_outq + a->udp_outq_len, data, len);
    a->udp_outq_len += len;
    pump_out(a);
}

static void pump_out(tm_agent_app *a) {
    if (a->udp_closing || !a->udp_ssl) return;
    if (a->udp_outq_len > 0) {
        int w = SSL_write(a->udp_ssl, a->udp_outq + a->udp_outq_off,
                          (int)(a->udp_outq_len - a->udp_outq_off));
        if (w <= 0) {
            int e = SSL_get_error(a->udp_ssl, w);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                return;
            tm_agent_udp_stop(a);
            return;
        }
        a->udp_outq_off += (size_t)w;
        if (a->udp_outq_off == a->udp_outq_len) {
            a->udp_outq_len = 0;
            a->udp_outq_off = 0;
        }
    }
    uint8_t chunk[TM_DEFAULT_DATAGRAM + 1024u];
    for (;;) {
        int n = BIO_read(a->udp_wbio, chunk, sizeof(chunk));
        if (n <= 0) break;
        udp_send_raw(a, chunk, (size_t)n);
    }
}

/* ------------------------------------------------------------------ */
/* local flows                                                         */
/* ------------------------------------------------------------------ */

static void flow_close(tm_agent_app *a, tm_alflow *f) {
    if (f->closing) return;
    f->closing = true;
    uv_udp_recv_stop(&f->sock);
    if (!uv_is_closing((uv_handle_t *)&f->sock))
        uv_close((uv_handle_t *)&f->sock, NULL);
    tm_alflow **pp = &a->udp_flows;
    while (*pp) {
        if (*pp == f) { *pp = f->next; break; }
        pp = &(*pp)->next;
    }
    free(f);
}

static tm_alflow *flow_find(tm_agent_app *a, uint64_t flow_id) {
    for (tm_alflow *f = a->udp_flows; f; f = f->next)
        if (f->flow_id == flow_id) return f;
    return NULL;
}

static void flow_alloc_cb(uv_handle_t *handle, size_t suggested, uv_buf_t *buf) {
    (void)handle; (void)suggested;
    buf->base = tm_xmalloc(TM_DEFAULT_DATAGRAM + 512u);
    buf->len = TM_DEFAULT_DATAGRAM + 512u;
}

static void flow_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                         const struct sockaddr *addr, unsigned flags) {
    (void)addr; (void)flags;
    tm_alflow *f = (tm_alflow *)handle->data;
    if (nread <= 0) { free(buf->base); return; }
    tm_agent_app *a = f->a;
    if (a->udp_closing || !a->udp_authed) { free(buf->base); return; }
    uint64_t now = tm_now_ms();
    if (now - f->pkt_win_start >= 1000) { f->pkt_win_start = now; f->pkt_win_count = 0; }
    if (f->pkt_win_count >= a->cfg.udp_max_packets_per_flow) { free(buf->base); return; }
    f->pkt_win_count++;
    f->last_seen_ms = now;
    size_t plen = (size_t)nread;
    if (plen > (size_t)a->cfg.udp_max_datagram_size) { free(buf->base); return; }
    size_t elen;
    uint8_t *env = tm_env_encode(f->flow_id, 0, (const uint8_t *)buf->base,
                                 (uint32_t)plen, &elen);
    free(buf->base);
    udp_queue(a, env, elen);
    free(env);
}

/* broker -> local */
static void handle_broker_env(tm_agent_app *a, uint64_t flow_id,
                              const uint8_t *payload, uint32_t plen) {
    if (flow_id == 0) return; /* keepalive */
    if (plen > (uint32_t)a->cfg.udp_max_datagram_size) return;
    tm_alflow *f = flow_find(a, flow_id);
    if (!f) {
        long long nf = 0;
        for (tm_alflow *x = a->udp_flows; x; x = x->next) nf++;
        if (nf >= a->cfg.udp_max_flows) return;
        uv_udp_t *sock = tm_xcalloc(1, sizeof(*sock));
        uv_udp_init(a->loop, sock);
        struct sockaddr_storage sa;
        if (tm_addr_parse(a->cfg.local_host, a->cfg.local_port, &sa) != TM_OK) {
            uv_close((uv_handle_t *)sock, NULL);
            free(sock);
            return;
        }
        if (uv_udp_connect(sock, (const struct sockaddr *)&sa) != 0) {
            uv_close((uv_handle_t *)sock, NULL);
            free(sock);
            return;
        }
        f = tm_xcalloc(1, sizeof(*f));
        f->flow_id = flow_id;
        f->a = a;
        f->sock = *sock;
        f->sock.data = f;
        f->last_seen_ms = tm_now_ms();
        free(sock);
        f->next = a->udp_flows;
        a->udp_flows = f;
        uv_udp_recv_start(&f->sock, flow_alloc_cb, flow_recv_cb);
    }
    f->last_seen_ms = tm_now_ms();
    uint8_t *copy = tm_xmalloc(plen);
    memcpy(copy, payload, plen);
    uv_buf_t b = uv_buf_init((char *)copy, (unsigned)plen);
    uv_udp_send_t *req = tm_xcalloc(1, sizeof(*req));
    tm_asend *wr = (tm_asend *)req;
    wr->buf = copy;
    uv_udp_send(req, &f->sock, &b, 1, NULL, send_done);
}

static void flow_sweep_cb(uv_timer_t *t) {
    tm_agent_app *a = (tm_agent_app *)t->data;
    if (!a) return;
    uint64_t now = tm_now_ms();
    tm_alflow *f = a->udp_flows;
    while (f) {
        tm_alflow *nxt = f->next;
        if (now - f->last_seen_ms > (uint64_t)a->cfg.udp_flow_idle_timeout_ms)
            flow_close(a, f);
        f = nxt;
    }
}

/* ------------------------------------------------------------------ */
/* inbound DTLS records                                               */
/* ------------------------------------------------------------------ */

static void udp_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags) {
    (void)addr; (void)flags;
    tm_agent_app *a = (tm_agent_app *)handle->data;
    if (nread <= 0) { free(buf->base); return; }
    if (a->udp_closing) { free(buf->base); return; }
    BIO_write(a->udp_rbio, buf->base, (int)nread);
    free(buf->base);

    if (!SSL_is_init_finished(a->udp_ssl)) {
        int r = SSL_connect(a->udp_ssl);
        int e = SSL_get_error(a->udp_ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            pump_out(a);
            return;
        }
        if (e != SSL_ERROR_NONE) {
            tm_log_warn(a->log, "udp_dtls_error", NULL, NULL,
                        "handshake failed (err=%d)", e);
            tm_agent_udp_stop(a);
            return;
        }
        if (SSL_is_init_finished(a->udp_ssl)) {
            /* send AUTH_REQ once */
            size_t elen;
            uint8_t *env = tm_env_encode(0, TM_ENV_FLAG_AUTH_REQ,
                                         (const uint8_t *)a->cfg.agent_secret,
                                         (uint32_t)strlen(a->cfg.agent_secret),
                                         &elen);
            udp_queue(a, env, elen);
            free(env);
        }
        pump_out(a);
        return;
    }

    /* established: read plaintext envelopes */
    uint8_t d[TM_DEFAULT_DATAGRAM + 1024u];
    for (;;) {
        int n = SSL_read(a->udp_ssl, d, sizeof(d));
        if (n <= 0) {
            int e = SSL_get_error(a->udp_ssl, n);
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
            if (!a->udp_authed) {
                a->udp_authed = true;
                tm_log_info(a->log, "udp_authed", NULL, NULL, "tunnel=%s",
                            a->cfg.tunnel_id);
            }
            continue;
        }
        if (eflags == TM_ENV_FLAG_AUTH_ERR) {
            tm_log_error(a->log, "udp_auth_rejected", NULL, NULL,
                         "tunnel=%s", a->cfg.tunnel_id);
            tm_agent_udp_stop(a);
            return;
        }
        if (eflags == 0) handle_broker_env(a, flow_id, payload, plen);
    }
    pump_out(a);
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                          */
/* ------------------------------------------------------------------ */

void tm_agent_udp_start(tm_agent_app *a) {
    if (a->udp_ssl) return; /* already running */
    uv_udp_init(a->loop, &a->udp_sock);
    a->udp_sock.data = a;
    a->udp_ssl = SSL_new(a->dtls_ctx);
    if (!a->udp_ssl) { uv_close((uv_handle_t *)&a->udp_sock, NULL); return; }
    a->udp_rbio = BIO_new(BIO_s_mem());
    a->udp_wbio = BIO_new(BIO_s_mem());
    if (!a->udp_rbio || !a->udp_wbio) {
        if (a->udp_rbio) BIO_free(a->udp_rbio);
        if (a->udp_wbio) BIO_free(a->udp_wbio);
        SSL_free(a->udp_ssl);
        a->udp_ssl = NULL;
        uv_close((uv_handle_t *)&a->udp_sock, NULL);
        return;
    }
    SSL_set_bio(a->udp_ssl, a->udp_rbio, a->udp_wbio);
    SSL_set_connect_state(a->udp_ssl);
    uv_udp_recv_start(&a->udp_sock, flow_alloc_cb, udp_recv_cb);
    uv_timer_init(a->loop, &a->udp_timer);
    a->udp_timer.data = a;
    uv_timer_start(&a->udp_timer, flow_sweep_cb, 15000, 15000);
    /* kick off the ClientHello */
    SSL_connect(a->udp_ssl);
    pump_out(a);
    tm_log_info(a->log, "udp_started", NULL, NULL, "%s:%u",
                a->cfg.broker_host, (unsigned)a->cfg.broker_port);
}

void tm_agent_udp_stop(tm_agent_app *a) {
    if (!a->udp_ssl && !a->udp_flows && !a->udp_outq) return;
    uv_udp_recv_stop(&a->udp_sock);
    if (!uv_is_closing((uv_handle_t *)&a->udp_sock))
        uv_close((uv_handle_t *)&a->udp_sock, NULL);
    uv_timer_stop(&a->udp_timer);
    if (!uv_is_closing((uv_handle_t *)&a->udp_timer))
        uv_close((uv_handle_t *)&a->udp_timer, NULL);
    while (a->udp_flows) flow_close(a, a->udp_flows);
    if (a->udp_ssl) { SSL_free(a->udp_ssl); a->udp_ssl = NULL; }
    a->udp_rbio = NULL;
    a->udp_wbio = NULL;
    free(a->udp_outq);
    a->udp_outq = NULL;
    a->udp_outq_len = a->udp_outq_cap = a->udp_outq_off = 0;
    a->udp_authed = false;
}