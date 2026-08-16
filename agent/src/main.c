#include "agent.h"
#include "tunnelmate/config.h"
#include "tunnelmate/log.h"
#include "tunnelmate/tls.h"
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static tm_agent_app *g_app;

static void agent_sig_handler(uv_signal_t *sig, int signum) {
    (void)sig;
    (void)signum;
    if (g_app) tm_agent_shutdown(g_app);
}

static int cfg_defaults(tm_agent_app *a) {
    tm_agent_cfg *c = &a->cfg;
    memset(c, 0, sizeof(*c));
    c->log_level = TM_LOG_INFO;
    c->proto = TM_PROTO_TCP;
    c->verify_ca = true;
    c->heartbeat_interval_ms = 5000;
    c->idle_timeout_ms = 30000;
    c->reconnect_delay_ms = 1000;
    c->reconnect_max_delay_ms = 30000;
    c->handshake_timeout_ms = 15000;
    c->local_connect_timeout_ms = 10000;
    c->udp_flow_idle_timeout_ms = 30000;
    c->udp_max_datagram_size = TM_DEFAULT_DATAGRAM;
    c->udp_max_packets_per_flow = 1000;
    c->udp_max_flows = 4096;
    return TM_OK;
}

static int cfg_apply(tm_agent_app *a, tm_config *c) {
    tm_agent_cfg *g = &a->cfg;
    const char *s;
    long long v;

    if (tm_config_get_str(c, "agent.broker_host", NULL, &s))
        strncpy(g->broker_host, s, sizeof(g->broker_host) - 1);
    if (tm_config_get_int(c, "agent.broker_port", 0, &v))
        g->broker_port = (uint16_t)v;
    if (tm_config_get_int(c, "agent.broker_udp_port", 0, &v))
        g->broker_udp_port = (uint16_t)v;
    if (tm_config_get_str(c, "agent.protocol", "tcp", &s)) {
        if (strcmp(s, "tcp") == 0) g->proto = TM_PROTO_TCP;
        else if (strcmp(s, "udp") == 0) g->proto = TM_PROTO_UDP;
        else return TM_ERR;
    }
    if (tm_config_get_str(c, "agent.tunnel_id", NULL, &s))
        strncpy(g->tunnel_id, s, sizeof(g->tunnel_id) - 1);
    if (tm_config_get_str(c, "agent.agent_secret", NULL, &s))
        strncpy(g->agent_secret, s, sizeof(g->agent_secret) - 1);
    if (tm_config_get_str(c, "agent.local_host", NULL, &s))
        strncpy(g->local_host, s, sizeof(g->local_host) - 1);
    if (tm_config_get_int(c, "agent.local_port", 0, &v))
        g->local_port = (uint16_t)v;
    if (tm_config_get_str(c, "agent.name", NULL, &s))
        strncpy(g->name, s, sizeof(g->name) - 1);
    if (tm_config_get_str(c, "agent.ca_path", NULL, &s))
        strncpy(g->ca_path, s, sizeof(g->ca_path) - 1);
    bool bv;
    if (tm_config_get_bool(c, "agent.verify_ca", true, &bv))
        g->verify_ca = bv;
    if (tm_config_get_str(c, "agent.log_level", "info", &s))
        tm_log_level_parse(s, &g->log_level);
    if (tm_config_get_int(c, "agent.heartbeat_interval_ms", 0, &v) && v > 0)
        g->heartbeat_interval_ms = v;
    if (tm_config_get_int(c, "agent.idle_timeout_ms", 0, &v) && v > 0)
        g->idle_timeout_ms = v;
    if (tm_config_get_int(c, "agent.reconnect_delay_ms", 0, &v) && v > 0)
        g->reconnect_delay_ms = v;
    if (tm_config_get_int(c, "agent.reconnect_max_delay_ms", 0, &v) && v > 0)
        g->reconnect_max_delay_ms = v;
    if (tm_config_get_int(c, "agent.handshake_timeout_ms", 0, &v) && v > 0)
        g->handshake_timeout_ms = v;
    if (tm_config_get_int(c, "agent.local_connect_timeout_ms", 0, &v) && v > 0)
        g->local_connect_timeout_ms = v;
    if (tm_config_get_int(c, "agent.udp_flow_idle_timeout_ms", 0, &v) && v > 0)
        g->udp_flow_idle_timeout_ms = v;
    if (tm_config_get_int(c, "agent.udp_max_datagram_size", 0, &v) && v > 0)
        g->udp_max_datagram_size = v;
    if (tm_config_get_int(c, "agent.udp_max_packets_per_flow", 0, &v) && v > 0)
        g->udp_max_packets_per_flow = v;
    if (tm_config_get_int(c, "agent.udp_max_flows", 0, &v) && v > 0)
        g->udp_max_flows = v;

    if (g->broker_host[0] == 0 || g->broker_port == 0) {
        tm_log_error(a->log, "bad_config", NULL, NULL,
                     "agent.broker_host and agent.broker_port required");
        return TM_ERR;
    }
    if (g->proto == TM_PROTO_UDP && g->broker_udp_port == 0) {
        tm_log_error(a->log, "bad_config", NULL, NULL,
                     "agent.broker_udp_port required for UDP tunnels");
        return TM_ERR;
    }
    if (g->tunnel_id[0] == 0 || g->agent_secret[0] == 0) {
        tm_log_error(a->log, "bad_config", NULL, NULL,
                     "agent.tunnel_id and agent.agent_secret required");
        return TM_ERR;
    }
    if (g->local_host[0] == 0 || g->local_port == 0) {
        tm_log_error(a->log, "bad_config", NULL, NULL,
                     "agent.local_host and agent.local_port required");
        return TM_ERR;
    }
    return TM_OK;
}

void tm_agent_shutdown(tm_agent_app *a) {
    if (a->shutting_down) return;
    a->shutting_down = true;
    tm_log_info(a->log, "shutdown", NULL, NULL, "stopping agent");
    uv_timer_stop(&a->reconnect_timer);
    if (a->ctl_io) { tm_io_close(a->ctl_io); a->ctl_io = NULL; }
    else if (a->ctl_ssl) { SSL_free(a->ctl_ssl); }
    a->ctl_ssl = NULL;
    if (!uv_is_closing((uv_handle_t *)&a->ctl_sock))
        uv_close((uv_handle_t *)&a->ctl_sock, NULL);
    uv_timer_stop(&a->hb_timer);
    uv_timer_stop(&a->hs_timer);
    tm_astream *st = a->streams;
    while (st) {
        tm_astream *nxt = st->next;
        tm_astream_close(a, st);
        st = nxt;
    }
    tm_agent_udp_stop(a);
    uv_stop(a->loop);
}

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s [-c CONFIG]\n", prog);
}

int main(int argc, char **argv) {
    const char *conf_path = "/etc/tunnelmate/tunnelmate.conf";
    if (argc >= 3 && strcmp(argv[1], "-c") == 0)
        conf_path = argv[2];
    else if (argc > 1) {
        usage(argv[0]);
        return 1;
    }

    tm_config *cfg = tm_config_new();
    char errbuf[256];
    if (tm_config_load(cfg, conf_path, errbuf, sizeof(errbuf)) != TM_OK) {
        fprintf(stderr, "tunnelmate-agent: %s: %s\n", conf_path, errbuf);
        tm_config_free(cfg);
        return 1;
    }

    tm_agent_app app;
    memset(&app, 0, sizeof(app));
    g_app = &app;
    app.loop = uv_default_loop();
    cfg_defaults(&app);
    app.log = tm_log_new(STDERR_FILENO, "agent", app.cfg.log_level);
    if (cfg_apply(&app, cfg) != TM_OK) {
        tm_config_free(cfg);
        return 1;
    }
    tm_log_free(app.log);
    app.log = tm_log_new(STDERR_FILENO, "agent", app.cfg.log_level);
    tm_config_free(cfg);

    app.ctl_fr = tm_frame_reader_new();
    uv_timer_init(app.loop, &app.hb_timer);
    app.hb_timer.data = &app;
    uv_timer_init(app.loop, &app.hs_timer);
    app.hs_timer.data = &app;
    uv_timer_init(app.loop, &app.reconnect_timer);
    app.reconnect_timer.data = &app;

    const char *ca = app.cfg.ca_path[0] ? app.cfg.ca_path : NULL;
    app.tls_ctx = tm_tls_client_ctx(ca, app.cfg.verify_ca, errbuf, sizeof(errbuf));
    if (!app.tls_ctx) { tm_log_error(app.log, "ssl_ctx", NULL, NULL, "%s", errbuf); return 1; }
    app.dtls_ctx = tm_dtls_client_ctx(ca, app.cfg.verify_ca, errbuf, sizeof(errbuf));
    if (!app.dtls_ctx) { tm_log_error(app.log, "ssl_ctx", NULL, NULL, "%s", errbuf); return 1; }

    uv_signal_t sigint, sigterm;
    uv_signal_init(app.loop, &sigint);
    uv_signal_start(&sigint, agent_sig_handler, SIGINT);
    uv_signal_init(app.loop, &sigterm);
    uv_signal_start(&sigterm, agent_sig_handler, SIGTERM);

    tm_log_info(app.log, "starting", NULL, NULL,
                "tunnelmate-agent (pid %ld) tunnel=%s local=%s:%u broker=%s:%u",
                (long)getpid(), app.cfg.tunnel_id, app.cfg.local_host,
                (unsigned)app.cfg.local_port, app.cfg.broker_host,
                (unsigned)app.cfg.broker_port);

    tm_agent_connect(&app);
    if (app.cfg.proto == TM_PROTO_UDP) tm_agent_udp_start(&app);

    uv_run(app.loop, UV_RUN_DEFAULT);

    uv_close((uv_handle_t *)&sigint, NULL);
    uv_close((uv_handle_t *)&sigterm, NULL);
    SSL_CTX_free(app.tls_ctx);
    SSL_CTX_free(app.dtls_ctx);
    tm_frame_reader_free(app.ctl_fr);
    tm_log_free(app.log);
    return 0;
}
