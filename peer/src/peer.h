#ifndef TM_PEER_H
#define TM_PEER_H

#include "tunnelmate/common.h"
#include "tunnelmate/io.h"
#include "tunnelmate/log.h"
#include "tunnelmate/frame.h"
#include "tunnelmate/config.h"
#include <uv.h>
#include <openssl/ssl.h>

typedef struct tm_peer tm_peer;
typedef struct tm_psess tm_psess;
typedef struct tm_pflow tm_pflow;

typedef struct {
    char broker_host[256];
    uint16_t broker_port;      /* control port (tcp mode) */
    uint16_t public_port;      /* public udp port (udp mode) */
    char tunnel_id[TM_MAX_TUNNEL_ID + 1];
    char token[TM_MAX_SECRET + 1];
    char listen_host[256];
    uint16_t listen_port;
    char ca_path[512];
    bool verify_ca;
    tm_proto proto;
    tm_log_level log_level;
    long long handshake_timeout_ms;
    long long idle_timeout_ms;
    long long reconnect_delay_ms;
    long long reconnect_max_delay_ms;
    long long udp_flow_idle_timeout_ms;
    long long udp_max_datagram_size;
    long long udp_max_flows;
} tm_peer_cfg;

/* one TCP session: local consumer connection + broker TLS connection.
   The broker connection authenticates (HELLO/AUTH), opens a stream with
   DATA_BIND(0), then becomes the raw relay leg. */
struct tm_psess {
    uv_tcp_t local_sock;
    uv_tcp_t broker_sock;
    uv_timer_t hs_timer;
    SSL *broker_ssl;
    tm_io *broker_io;      /* TLS leg to broker */
    tm_io *local_io;       /* raw local leg */
    tm_frame_reader *fr;   /* until DATA_BIND_OK */
    bool bound;
    bool local_eof;
    bool broker_eof;
    bool local_paused;
    bool broker_paused;
    bool local_fin, broker_fin;
    bool closing;
    bool connecting;
    int closing_refs;
    bool got_hello;
    uint8_t *pending_buf;  /* bytes that arrived before local bound */
    size_t pending_len;
    size_t pending_cap;
    uint8_t *pend_buf;     /* bytes queued while broker_io was busy */
    size_t pend_len;
    size_t pend_cap;
    tm_peer *p;
    tm_psess *next;
};

/* one local UDP flow (source addr) mapped to a broker flow id */
struct tm_pflow {
    uint64_t flow_id;
    struct sockaddr_storage src;
    uint64_t last_seen_ms;
    tm_peer *p;
    tm_pflow *next;
};

struct tm_peer {
    tm_peer_cfg cfg;
    tm_logger *log;
    uv_loop_t *loop;
    SSL_CTX *tls_ctx;    /* TLS client */
    SSL_CTX *dtls_ctx;   /* DTLS client */

    /* tcp mode */
    uv_tcp_t listener;
    bool listening;
    tm_psess *sessions;

    /* udp mode */
    uv_udp_t broker_udp;   /* DTLS session to broker public port */
    uv_udp_t local_udp;    /* local listener for consumer apps */
    SSL *udp_ssl;
    BIO *udp_rbio, *udp_wbio;
    uv_timer_t udp_timer;
    uv_timer_t udp_flow_timer;
    uv_timer_t reconnect_timer;
    uint64_t reconnect_delay_ms;
    bool udp_authed;
    bool udp_closing;
    uint8_t *udp_outq;
    size_t udp_outq_len, udp_outq_cap, udp_outq_off;
    size_t udp_outq_packets;
    uint64_t next_flow_id;
    tm_pflow *udp_flows;

    bool shutting_down;
};

/* main.c */
int tm_peer_run(tm_peer *p);
void tm_peer_shutdown(tm_peer *p);

/* tcp.c */
void tm_psess_close(tm_peer *p, tm_psess *s);
int tm_peer_tcp_listen(tm_peer *p);

/* udp.c */
void tm_peer_udp_start(tm_peer *p);
void tm_peer_udp_stop(tm_peer *p);

#endif
