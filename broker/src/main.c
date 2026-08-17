#include "broker.h"
#include "tunnelmate/config.h"
#include "tunnelmate/crypto.h"
#include "tunnelmate/net.h"

#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static tm_broker g_broker;

/* ------------------------------------------------------------------ */
/* config                                                              */
/* ------------------------------------------------------------------ */

static const char *cfg_get_str(const tm_config *c, const char *k, const char *def,
                               char *out, size_t outlen) {
    const char *v = tm_config_get_str_owned(c, k, def);
    snprintf(out, outlen, "%s", v ? v : "");
    return out;
}

static long long cfg_get_int(const tm_config *c, const char *k, long long def) {
    long long v;
    tm_config_get_int(c, k, def, &v);
    return v;
}

static void cfg_load(tm_broker *b, tm_config *c) {
    tm_broker_cfg *cfg = &b->cfg;
    memset(cfg, 0, sizeof(*cfg));
    cfg_get_str(c, "broker.listen_host", "0.0.0.0", cfg->listen_host,
                sizeof(cfg->listen_host));
    cfg->control_port = (uint16_t)cfg_get_int(c, "broker.control_port", 7000);
    cfg->public_port_start = (uint16_t)cfg_get_int(c, "broker.public_port_start",
                                                   TM_PORT_START_DEFAULT);
    cfg->public_port_end = (uint16_t)cfg_get_int(c, "broker.public_port_end",
                                                 TM_PORT_END_DEFAULT);
    cfg_get_str(c, "broker.tls_cert", "/etc/tunnelmate/certs/broker.crt",
                cfg->tls_cert, sizeof(cfg->tls_cert));
    cfg_get_str(c, "broker.tls_key", "/etc/tunnelmate/certs/broker.key",
                cfg->tls_key, sizeof(cfg->tls_key));
    cfg_get_str(c, "broker.hmac_key_file", "/etc/tunnelmate/hmac.key",
                cfg->hmac_key_file, sizeof(cfg->hmac_key_file));
    cfg_get_str(c, "broker.broker_socket", "/run/tunnelmate/broker.sock",
                cfg->broker_socket, sizeof(cfg->broker_socket));
    cfg_get_str(c, "broker.log_level", "info", cfg->log_level, sizeof(cfg->log_level));
    tm_log_level_parse(cfg->log_level, &cfg->log_level_parsed);

    cfg->max_tunnels = cfg_get_int(c, "broker.max_tunnels", 256);
    cfg->max_streams = cfg_get_int(c, "broker.max_streams", 4096);
    cfg->max_streams_per_tunnel = cfg_get_int(c, "broker.max_streams_per_tunnel", 256);
    cfg->max_pending_streams = cfg_get_int(c, "broker.max_pending_streams", 256);
    cfg->handshake_timeout_ms = cfg_get_int(c, "broker.handshake_timeout_ms", 15000);
    cfg->idle_timeout_ms = cfg_get_int(c, "broker.idle_timeout_ms", 90000);
    cfg->heartbeat_interval_ms = cfg_get_int(c, "broker.heartbeat_interval_ms", 15000);
    cfg->bind_timeout_ms = cfg_get_int(c, "broker.bind_timeout_ms", 10000);
    cfg->shutdown_grace_ms = cfg_get_int(c, "broker.shutdown_grace_ms", 5000);

    cfg->udp_flow_idle_timeout_ms = cfg_get_int(c, "broker.udp_flow_idle_timeout_ms", 30000);
    cfg->udp_max_flows = cfg_get_int(c, "broker.udp_max_flows", 65536);
    cfg->udp_max_flows_per_tunnel = cfg_get_int(c, "broker.udp_max_flows_per_tunnel", 4096);
    cfg->udp_max_datagram_size = cfg_get_int(c, "broker.udp_max_datagram_size", TM_DEFAULT_DATAGRAM);
    cfg->udp_max_packets_per_tunnel = cfg_get_int(c, "broker.udp_max_packets_per_tunnel", 2000);
    cfg->udp_max_packets_per_source = cfg_get_int(c, "broker.udp_max_packets_per_source", 200);
    cfg->udp_flow_creation_rate = cfg_get_int(c, "broker.udp_flow_creation_rate", 50);
    cfg->udp_queue_packets = cfg_get_int(c, "broker.udp_queue_packets", 1024);
    cfg->connect_rate_per_ip = cfg_get_int(c, "broker.connect_rate_per_ip", 30);
}

/* ------------------------------------------------------------------ */
/* TLS contexts                                                        */
/* ------------------------------------------------------------------ */

static SSL_CTX *ctx_new(tm_broker *b, bool dtls) {
    SSL_CTX *ctx;
    if (dtls) {
        ctx = SSL_CTX_new(DTLS_server_method());
        SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, DTLS1_2_VERSION);
        SSL_CTX_set_read_ahead(ctx, 1);
        SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);
    } else {
        ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    }
    if (!ctx) {
        tm_log_error(b->log, "tls_ctx_failed", NULL, NULL, "SSL_CTX_new");
        return NULL;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (SSL_CTX_use_certificate_chain_file(ctx, b->cfg.tls_cert) != 1) {
        tm_log_error(b->log, "tls_cert_failed", NULL, NULL, "%s", b->cfg.tls_cert);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, b->cfg.tls_key, SSL_FILETYPE_PEM) != 1) {
        tm_log_error(b->log, "tls_key_failed", NULL, NULL, "%s", b->cfg.tls_key);
        return NULL;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        tm_log_error(b->log, "tls_key_mismatch", NULL, NULL, "%s", b->cfg.tls_key);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

/* ------------------------------------------------------------------ */
/* hmac key                                                            */
/* ------------------------------------------------------------------ */

static void hmac_key_load(tm_broker *b) {
    FILE *f = fopen(b->cfg.hmac_key_file, "rb");
    if (f) {
        size_t n = fread(b->hmac_key, 1, sizeof(b->hmac_key), f);
        fclose(f);
        if (n == sizeof(b->hmac_key)) {
            b->hmac_key_loaded = true;
            return;
        }
    }
    /* generate + persist with strict permissions */
    if (tm_rand_bytes(b->hmac_key, sizeof(b->hmac_key)) != TM_OK) {
        tm_log_error(b->log, "hmac_key_gen_failed", NULL, NULL, "rng");
        exit(1);
    }
    int fd = open(b->cfg.hmac_key_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        tm_log_error(b->log, "hmac_key_write_failed", NULL, NULL, "%s",
                     b->cfg.hmac_key_file);
        exit(1);
    }
    size_t off = 0;
    while (off < sizeof(b->hmac_key)) {
        ssize_t w = write(fd, b->hmac_key + off, sizeof(b->hmac_key) - off);
        if (w <= 0) {
            close(fd);
            exit(1);
        }
        off += (size_t)w;
    }
    close(fd);
    chmod(b->cfg.hmac_key_file, 0600);
    b->hmac_key_loaded = true;
}

/* ------------------------------------------------------------------ */
/* shutdown                                                            */
/* ------------------------------------------------------------------ */

static void broker_cleanup(tm_broker *b) {
    if (b->cleaned_up) return;
    b->cleaned_up = true;
    tm_control_close_all(b);
    tm_tunnel *t = b->tunnels;
    while (t) {
        tm_tunnel *nxt = t->next;
        tm_tunnel_teardown(b, t);
        t = nxt;
    }
    b->tunnels = NULL;
    if (b->ipc_open) {
        uv_close((uv_handle_t *)&b->ipc_pipe, NULL);
        b->ipc_open = false;
    }
    if (b->tls_ctx) { SSL_CTX_free(b->tls_ctx); b->tls_ctx = NULL; }
    if (b->dtls_ctx) { SSL_CTX_free(b->dtls_ctx); b->dtls_ctx = NULL; }
    if (b->ports_tcp) { free(b->ports_tcp); b->ports_tcp = NULL; }
    if (b->ports_udp) { free(b->ports_udp); b->ports_udp = NULL; }
    unlink(b->cfg.broker_socket);
}

static void shutdown_timer_cb(uv_timer_t *t) {
    tm_broker *b = (tm_broker *)t->data;
    uv_stop(b->loop);
    broker_cleanup(b);
    tm_log_info(b->log, "shutdown_complete", NULL, NULL, "bye");
}

void tm_broker_shutdown(tm_broker *b) {
    if (b->shutting_down) return;
    b->shutting_down = true;
    tm_log_info(b->log, "shutdown_start", NULL, NULL, "graceful");
    /* stop accepting */
    if (b->control_listening) {
        uv_close((uv_handle_t *)&b->control_listener, NULL);
        b->control_listening = false;
    }
    tm_control_goaway_all(b);
    uv_timer_init(b->loop, &b->shutdown_timer);
    b->shutdown_timer.data = b;
    uv_timer_start(&b->shutdown_timer, shutdown_timer_cb,
                   (uint64_t)b->cfg.shutdown_grace_ms, 0);
}

static void on_signal(uv_signal_t *s, int signum) {
    tm_broker *b = (tm_broker *)s->data;
    (void)signum;
    tm_broker_shutdown(b);
}

/* ------------------------------------------------------------------ */
/* run                                                                 */
/* ------------------------------------------------------------------ */

int tm_broker_run(tm_broker *b) {
    b->start_ms = tm_now_ms();
    b->loop = uv_default_loop();

    tm_control_listener_start(b);
    /* Without IPC the control plane can never manage this broker; fail loudly
       at startup rather than serving an unmanageable process. */
    if (tm_ipc_start(b) != TM_OK) return 1;

    uv_signal_t sigint, sigterm;
    uv_signal_init(b->loop, &sigint);
    sigint.data = b;
    uv_signal_start(&sigint, on_signal, SIGINT);
    uv_signal_init(b->loop, &sigterm);
    sigterm.data = b;
    uv_signal_start(&sigterm, on_signal, SIGTERM);

    tm_log_info(b->log, "broker_started", "version", NULL, TM_PROTO_STRING);
    (void)uv_run(b->loop, UV_RUN_DEFAULT);
    return 0;
}

int main(int argc, char **argv) {
    tm_ignore_sigpipe();
    const char *conf_path = "/etc/tunnelmate/tunnelmate.conf";
    if (argc > 1 && strcmp(argv[1], "-c") == 0 && argc > 2)
        conf_path = argv[2];

    tm_broker *b = &g_broker;
    memset(b, 0, sizeof(*b));

    /* logger to stderr */
    b->log = tm_log_new(2, "broker", TM_LOG_INFO);

    tm_config *cfg = tm_config_new();
    char errbuf[256];
    if (tm_config_load(cfg, conf_path, errbuf, sizeof(errbuf)) != TM_OK) {
        /* defaults still apply */
        tm_log_warn(b->log, "config_load_failed", "path", NULL, "%s: %s",
                    conf_path, errbuf);
    }
    cfg_load(b, cfg);
    tm_config_free(cfg);
    /* apply parsed level now that config is known */
    tm_log_free(b->log);
    b->log = tm_log_new(2, "broker", b->cfg.log_level_parsed);

    /* A single-port range (start == end) is legal and useful for tests. */
    if (b->cfg.public_port_end < b->cfg.public_port_start) {
        tm_log_error(b->log, "bad_port_range", NULL, NULL, "%u..%u",
                     (unsigned)b->cfg.public_port_start,
                     (unsigned)b->cfg.public_port_end);
        return 1;
    }
    size_t n = (size_t)(b->cfg.public_port_end - b->cfg.public_port_start) + 1;
    b->ports_tcp = tm_xcalloc(n, 1);
    b->ports_udp = tm_xcalloc(n, 1);

    hmac_key_load(b);

    b->tls_ctx = ctx_new(b, false);
    b->dtls_ctx = ctx_new(b, true);
    if (!b->tls_ctx || !b->dtls_ctx) return 1;

    int rc = tm_broker_run(b);

    broker_cleanup(b);
    tm_log_free(b->log);
    return rc;
}
