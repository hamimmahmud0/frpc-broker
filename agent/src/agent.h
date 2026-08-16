#ifndef TM_AGENT_H
#define TM_AGENT_H

#include "tunnelmate/common.h"

#ifndef TM_TUNNEL_ID_LEN
#define TM_TUNNEL_ID_LEN 24
#endif
#include "tunnelmate/io.h"
#include "tunnelmate/log.h"
#include "tunnelmate/config.h"
#include "tunnelmate/frame.h"
#include <uv.h>
#include <openssl/ssl.h>

typedef struct tm_agent_app tm_agent_app;
typedef struct tm_astream tm_astream;
typedef struct tm_alflow tm_alflow;

typedef struct {
    char broker_host[256];
    uint16_t broker_port;
    char tunnel_id[TM_TUNNEL_ID_LEN + 1];
    char agent_secret[TM_MAX_SECRET + 1];
    char local_host[256];
    uint16_t local_port;
    char name[TM_MAX_AGENT_NAME + 1];
    tm_log_level log_level;
    long long heartbeat_interval_ms;
    long long idle_timeout_ms;
    long long reconnect_delay_ms;
    long long reconnect_max_delay_ms;
    long long handshake_timeout_ms;
    long long local_connect_timeout_ms;
    long long udp_flow_idle_timeout_ms;
    long long udp_max_datagram_size;
    long long udp_max_packets_per_flow;
    long long udp_max_flows;
} tm_agent_cfg;

/* one relayed TCP stream: broker data conn + local service conn */
struct tm_astream {
    uint32_t sid;
    uv_tcp_t broker_sock;    /* data connection socket */
    uv_tcp_t local_sock;     /* local service socket */
    uv_timer_t connect_timer;
    SSL *broker_ssl;
    tm_io *broker_io;        /* TLS 1.2 leg */
    tm_io *local_io;         /* raw leg */
    tm_frame_reader *fr;     /* until DATA_BIND_OK */
    bool bound;
    bool local_eof;
    bool broker_eof;
    bool local_paused;
    bool broker_paused;
    bool local_fin, broker_fin;
    bool closing;
    bool connecting;
    int closing_refs;
    uint8_t *pending_buf;   /* bytes that arrived before local bound */
    size_t pending_len;
    size_t pending_cap;
    uint8_t *pend_buf;      /* bytes queued while broker_io was busy */
    size_t pend_len;
    size_t pend_cap;
    uint64_t created_ms;
    uint64_t up_bytes;   /* broker -> local relayed */
    uint64_t down_bytes; /* local -> broker relayed */
    tm_agent_app *a;
    tm_astream *next;
};

/* one local UDP flow (connected socket), keyed by broker flow id */
struct tm_alflow {
    uint64_t flow_id;
    uv_udp_t sock;
    uint64_t last_seen_ms;
    uint64_t pkt_win_start;
    long long pkt_win_count;
    bool closing;
    tm_agent_app *a;
    tm_alflow *next;
};

struct tm_agent_app {
    tm_agent_cfg cfg;
    tm_logger *log;
    uv_loop_t *loop;
    SSL_CTX *tls_ctx;    /* TLS client (control + data) */
    SSL_CTX *dtls_ctx;   /* DTLS client (udp plane) */

    /* control connection */
    uv_tcp_t ctl_sock;
    SSL *ctl_ssl;
    tm_io *ctl_io;
    tm_frame_reader *ctl_fr;
    uv_timer_t hb_timer;
    uv_timer_t hs_timer;
    bool connected;
    bool got_hello;
    bool registered;
    uint64_t last_rx_ms;
    uint64_t last_ping_ms;

    /* reconnect */
    uv_timer_t reconnect_timer;
    uint64_t reconnect_delay_ms;

    /* streams */
    tm_astream *streams;
    long long stream_count;

    /* udp */
    uv_udp_t udp_sock;
    SSL *udp_ssl;
    BIO *udp_rbio, *udp_wbio;
    uv_timer_t udp_timer;
    uv_timer_t udp_flow_timer;
    bool udp_authed;
    bool udp_closing;
    uint8_t *udp_outq;
    size_t udp_outq_len, udp_outq_cap, udp_outq_off;
    tm_alflow *udp_flows;
    bool shutting_down;
};

/* control.c */
void tm_agent_connect(tm_agent_app *a);
void tm_agent_disconnect(tm_agent_app *a, const char *reason);
void tm_agent_send_frame(tm_agent_app *a, tm_frame *f);

/* tcp.c */
void tm_astream_open(tm_agent_app *a, uint32_t sid);
void tm_astream_close(tm_agent_app *a, tm_astream *st);
tm_astream *tm_astream_find(tm_agent_app *a, uint32_t sid);

/* udp.c */
void tm_agent_udp_start(tm_agent_app *a);
void tm_agent_udp_stop(tm_agent_app *a);

/* main.c */
void tm_agent_shutdown(tm_agent_app *a);

#endif