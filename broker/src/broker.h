#ifndef TM_BROKER_H
#define TM_BROKER_H

#include "tunnelmate/common.h"
#include "tunnelmate/io.h"
#include "tunnelmate/log.h"
#include "tunnelmate/config.h"
#include "tunnelmate/frame.h"
#include <uv.h>
#include <openssl/ssl.h>

#define TM_TUNNEL_ID_LEN 24

typedef struct tm_broker tm_broker;
typedef struct tm_tunnel tm_tunnel;
typedef struct tm_agent tm_agent;
typedef struct tm_stream tm_stream;
typedef struct tm_udp_session tm_udp_session;
typedef struct tm_udp_flow tm_udp_flow;
typedef struct tm_conn tm_conn;

/* ---------------------------------------------------------------- */
/* broker config                                                     */
/* ---------------------------------------------------------------- */

typedef struct {
    char listen_host[64];
    uint16_t control_port;
    uint16_t public_port_start;
    uint16_t public_port_end;
    char tls_cert[512];
    char tls_key[512];
    char hmac_key_file[512];
    char broker_socket[512];
    char log_level[16];
    tm_log_level log_level_parsed;

    long long max_tunnels;
    long long max_streams;
    long long max_streams_per_tunnel;
    long long max_pending_streams;
    long long handshake_timeout_ms;
    long long idle_timeout_ms;
    long long heartbeat_interval_ms;
    long long bind_timeout_ms;
    long long shutdown_grace_ms;

    long long udp_flow_idle_timeout_ms;
    long long udp_max_flows;
    long long udp_max_flows_per_tunnel;
    long long udp_max_datagram_size;
    long long udp_max_packets_per_tunnel;   /* per second */
    long long udp_max_packets_per_source;   /* per second */
    long long udp_flow_creation_rate;       /* per second per tunnel */
    long long udp_queue_packets;

    long long connect_rate_per_ip;          /* public conns per second per ip */
} tm_broker_cfg;

/* ---------------------------------------------------------------- */
/* tunnel                                                            */
/* ---------------------------------------------------------------- */

struct tm_tunnel {
    char id[TM_TUNNEL_ID_LEN + 1];
    tm_proto proto;
    bool closed;
    bool enabled;
    uint16_t public_port;
    char agent_secret_hmac[65];
    char shared_token_hmac[65];
    uint64_t created_at_ms;
    uint64_t last_seen_ms;
    uint64_t expires_at_ms;          /* 0 = no expiry (admin set) */

    tm_agent *agent;                 /* control session when online */
    bool agent_online;

    /* TCP */
    uv_tcp_t listener;
    bool listener_open;
    /* uv_close() is asynchronous: the handle memory may not be re-initialised
       until its close callback runs. A start requested while a close is in
       flight is deferred to that callback. */
    bool listener_closing;
    bool listener_restart_pending;

    /* UDP */
    uv_udp_t udp_sock;
    bool udp_open;
    tm_udp_session *udp_sessions;
    tm_udp_session *agent_session;   /* authenticated agent DTLS session */
    tm_udp_flow *udp_flows;
    uint64_t next_flow_id;
    long long udp_flow_created_win_start;   /* ms */
    long long udp_flow_created_win_count;
    long long udp_pkt_win_start;            /* ms */
    long long udp_pkt_win_count;

    /* streams */
    tm_stream *streams;
    long long streams_active;

    /* stats */
    uint64_t rx_bytes, tx_bytes;
    uint64_t datagrams_rx, datagrams_tx;
    uint64_t streams_total;
    uint64_t conns_rejected_offline;

    tm_broker *b;
    tm_tunnel *next;
    bool deleting;
    int close_refs;
};

/* ---------------------------------------------------------------- */
/* control session (agent)                                           */
/* ---------------------------------------------------------------- */

struct tm_agent {
    tm_tunnel *tun;
    uv_tcp_t *sock;      /* heap-allocated at accept; closed+freed here */
    uv_timer_t hb_timer;
    tm_io *io;
    tm_frame_reader *fr;
    uint64_t last_rx_ms;
    uint64_t last_ping_ms;
    bool ping_outstanding;
    bool closing;
    bool got_hello;
    char remote[128];
    tm_broker *b;
};

/* ---------------------------------------------------------------- */
/* TCP stream                                                        */
/* ---------------------------------------------------------------- */

struct tm_stream {
    uint32_t id;
    tm_tunnel *tun;
    uv_handle_t *sock_a;     /* consumer leg socket handle (owned) */
    uv_handle_t *sock_b;     /* agent leg socket handle (owned) */
    uv_timer_t bind_timer;
    tm_io *io_a;
    tm_io *io_b;
    bool bound;
    bool a_eof;
    bool b_eof;
    bool closing;
    bool a_paused;
    bool b_paused;
    uint64_t start_ms;
    uint64_t up_bytes;   /* public -> agent relayed */
    uint64_t down_bytes; /* agent -> public relayed */
    struct sockaddr_storage peer_addr;
    tm_broker *b;
    tm_stream *next;   /* per-tunnel list */
    /* closed-tunnel leg A bytes arriving before the agent leg binds */
    uint8_t *preq;
    size_t preq_len, preq_cap;
    /* bytes queued while the target io's write queue is full */
    uint8_t *pend_a; /* destined for io_a (from leg B) */
    size_t pend_a_len, pend_a_cap;
    uint8_t *pend_b; /* destined for io_b (from leg A) */
    size_t pend_b_len, pend_b_cap;
    bool a_fin, b_fin; /* FIN sent to io_b / io_a once the pend drained */
    /* Set while flush_pend is walking that queue. A synchronous drain inside
       tm_io_write fires the low-water callback, which re-enters flush_pend;
       these keep the inner pass from consuming the slice the outer loop is
       still holding. */
    bool flushing_a, flushing_b;
};

/* ---------------------------------------------------------------- */
/* UDP session / flow                                                */
/* ---------------------------------------------------------------- */

struct tm_udp_session {
    tm_tunnel *tun;
    SSL *ssl;
    BIO *rbio, *wbio;
    uv_timer_t timer;
    struct sockaddr_storage peer;
    bool is_agent;         /* agent session vs closed-peer session */
    bool authenticated;    /* sessions must AUTH inside DTLS */
    bool handshake_done;
    bool inflight;
    bool closing;
    bool timer_closed;
    uint64_t last_rx_ms;
    uint64_t pkts_rx, pkts_tx;
    long long pkt_win_start;
    long long pkt_win_count;
    /* outbound plaintext queue (envelopes), encrypted in pump */
    uint8_t *outq;
    size_t outq_len, outq_cap, outq_off;
    size_t outq_packets;
    tm_broker *b;
    tm_udp_session *next;
};

struct tm_udp_flow {
    uint64_t flow_id;            /* broker-assigned (agent-facing) */
    uint64_t src_flow_id;        /* flow id used by client/peer */
    tm_tunnel *tun;
    bool from_peer_session;
    struct sockaddr_storage src;        /* open tunnels: client addr */
    tm_udp_session *peer_session;       /* closed tunnels */
    uv_timer_t idle_timer;
    uint64_t last_seen_ms;
    uint64_t pkts_rx, pkts_tx, bytes_rx, bytes_tx;
    long long pkt_win_start;
    long long pkt_win_count;
    tm_broker *b;
    tm_udp_flow *next;
};

/* ---------------------------------------------------------------- */
/* broker                                                            */
/* ---------------------------------------------------------------- */

struct tm_broker {
    tm_broker_cfg cfg;
    tm_logger *log;
    uv_loop_t *loop;
    SSL_CTX *tls_ctx;        /* TLS 1.3 control/data listener */
    SSL_CTX *dtls_ctx;       /* DTLS server for udp sessions */

    uv_tcp_t control_listener;
    bool control_listening;

    uint8_t hmac_key[32];
    bool hmac_key_loaded;

    tm_tunnel *tunnels;      /* registry (by id) */
    long long tunnel_count;
    long long stream_count;

    /* port allocation: bitmap-free scan per (proto) namespace */
    bool *ports_tcp;         /* size = port range */
    bool *ports_udp;
    uint16_t ports_used;

    /* metrics */
    uint64_t start_ms;
    uint64_t rx_bytes_total, tx_bytes_total;
    uint64_t datagrams_rx_total, datagrams_tx_total;
    uint64_t streams_total, flows_total;
    uint64_t failed_auths;
    uint64_t protocol_errors;
    uint64_t agent_reconnects;
    uint64_t conns_total;
    uint64_t conns_rate_limited;
    uint64_t udp_dropped_queue_full;
    uint64_t udp_dropped_oversize;
    uint64_t udp_dropped_rate_limit;
    uint64_t udp_dropped_no_flow;
    uint64_t udp_flow_expired;
    uint64_t stream_errors;

    /* IPC */
    uv_pipe_t ipc_pipe;
    bool ipc_open;
    /* pending ipc connection state */
    uv_stream_t *ipc_client;
    char ipc_rbuf[16384];
    size_t ipc_rbuf_len;

    /* shutdown */
    bool shutting_down;
    bool cleaned_up;
    uv_timer_t shutdown_timer;

    /* pending control-port connections (pre-promotion) */
    tm_conn *conns;
    /* control heartbeat / idle sweep */
    uv_timer_t control_tick;

    /* public listeners list (for shutdown) */
    struct tm_listener *listeners;

    /* per-source-IP accept rate limiter (TCP public listeners) */
    struct tm_accept_rate *accept_rates;
};

/* relay.c */
void tm_stream_relay_attach_agent(tm_broker *b, tm_stream *st, tm_io *io,
                                  uv_handle_t *sock_b);
void tm_stream_ingest(tm_stream *st, const uint8_t *data, size_t len);
void tm_stream_ingest_a(tm_stream *st, const uint8_t *data, size_t len);
void tm_stream_close(tm_broker *b, tm_stream *st);
tm_stream *tm_stream_find(tm_broker *b, tm_tunnel *tun, uint32_t id);
tm_stream *tm_stream_create_open(tm_broker *b, tm_tunnel *tun, uv_tcp_t *public_sock);
tm_stream *tm_stream_create_closed(tm_broker *b, tm_tunnel *tun, tm_io *peer_io,
                                   uv_handle_t *peer_sock);

/* control.c */
void tm_control_listener_start(tm_broker *b);
void tm_agent_drop(tm_broker *b, tm_agent *a, const char *reason);
void tm_agent_send_frame(tm_broker *b, tm_agent *a, tm_frame *f);
void tm_agent_tick(tm_broker *b);
void tm_control_goaway_all(tm_broker *b);
void tm_control_close_all(tm_broker *b);

/* tcp.c */
void tm_tunnel_listener_start(tm_broker *b, tm_tunnel *tun);
void tm_tunnel_listener_stop(tm_broker *b, tm_tunnel *tun);

/* udp.c */
void tm_udp_start(tm_broker *b, tm_tunnel *tun);
void tm_udp_stop(tm_broker *b, tm_tunnel *tun);
void tm_udp_flow_expire(tm_broker *b, tm_udp_flow *f);
void tm_udp_session_close(tm_broker *b, tm_udp_session *s);

/* registry.c */
tm_tunnel *tm_tunnel_find(tm_broker *b, const char *id);
tm_tunnel *tm_tunnel_create(tm_broker *b, const char *id, tm_proto proto,
                            bool closed, const char *agent_hmac,
                            const char *token_hmac, uint16_t prefer_port,
                            uint16_t *allocated);
int tm_tunnel_delete(tm_broker *b, const char *id, char *err, size_t errlen);
void tm_tunnel_teardown(tm_broker *b, tm_tunnel *t);
uint16_t tm_port_alloc(tm_broker *b, tm_proto proto, uint16_t prefer);
void tm_port_free(tm_broker *b, tm_proto proto, uint16_t port);
bool tm_port_in_range(tm_broker *b, uint16_t port);

/* metrics.c */
void tm_metrics_start(tm_broker *b);
char *tm_metrics_json(tm_broker *b, bool include_tunnels);

/* ipc.c */
tm_status tm_ipc_start(tm_broker *b);

/* main helpers */
int tm_broker_run(tm_broker *b);
void tm_broker_shutdown(tm_broker *b);

/* tls.c (broker side helpers) */
SSL *tm_broker_accept_ssl(tm_broker *b, bool tls13);
void tm_broker_tls_free_handle_cb(uv_handle_t *h);

#endif
