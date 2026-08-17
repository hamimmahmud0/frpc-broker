#include "peer.h"
#include "tunnelmate/crypto.h"
#include "tunnelmate/net.h"
#include "tunnelmate/tls.h"

#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* tunnelmate-peer: consumer-side access to closed tunnels.
   Usage: tunnelmate-peer connect tunnel://host[:port]/<tunnel-id>
              --token TOKEN|--token-file FILE --listen HOST:PORT
              [--protocol tcp|udp] [--ca FILE] [--no-verify-ca] */

static void usage(FILE *out) {
    fprintf(out,
        "Usage: tunnelmate-peer connect <tunnel://host[:port]/<tunnel-id>>"
        " [options]\n"
        "\n"
        "Connect to a closed TunnelMate tunnel and expose it locally.\n"
        "\n"
        "Arguments:\n"
        "  tunnel://host[:port]/<tunnel-id>   broker address and tunnel id\n"
        "                                     (port: control port, default 7000;\n"
        "                                      in UDP mode this is the tunnel's\n"
        "                                      public UDP port)\n"
        "\n"
        "Options:\n"
        "  --token TOKEN          shared token for the tunnel (required)\n"
        "  --token-file FILE      read token from a protected file\n"
        "  --listen HOST:PORT     local address to expose (required)\n"
        "  --protocol tcp|udp     tunnel protocol (default: tcp)\n"
        "  --ca FILE              CA bundle to verify the broker certificate\n"
        "  --no-verify-ca         do not verify the broker certificate\n"
        "  --log-level LEVEL      debug|info|warn|error (default: info)\n"
        "  -h, --help             show this help\n");
}

static tm_peer *g_peer;

static void on_signal(uv_signal_t *s, int signum) {
    (void)signum;
    tm_peer *p = (tm_peer *)s->data;
    tm_peer_shutdown(p);
}

/* parse tunnel://host[:port]/<id> */
static int parse_tunnel_url(tm_peer_cfg *cfg, const char *url) {
    if (strncmp(url, "tunnel://", 9) != 0) return -1;
    const char *rest = url + 9;
    const char *slash = strchr(rest, '/');
    if (!slash || slash == rest) return -1;
    size_t hostlen = (size_t)(slash - rest);
    char host[512];
    if (hostlen >= sizeof(host)) return -1;
    memcpy(host, rest, hostlen);
    host[hostlen] = '\0';

    const char *tunnel_id = slash + 1;
    size_t idlen = strlen(tunnel_id);
    if (idlen == 0 || idlen > TM_MAX_TUNNEL_ID) return -1;

    /* host may be bracketed IPv6: [::1]:7000 */
    uint16_t port = 7000;
    if (host[0] == '[') {
        char *close = strchr(host, ']');
        if (!close) return -1;
        size_t inner = (size_t)(close - host - 1);
        memmove(host, host + 1, inner);
        host[inner] = '\0';
        char *after = close + 1;
        if (*after == ':') {
            char *end = NULL;
            long v = strtol(after + 1, &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 65535) return -1;
            port = (uint16_t)v;
        } else if (*after != '\0') {
            return -1;
        }
    } else {
        char *colon = strrchr(host, ':');
        if (colon) {
            char *end = NULL;
            long v = strtol(colon + 1, &end, 10);
            if (!end || *end != '\0' || v < 1 || v > 65535) return -1;
            port = (uint16_t)v;
            *colon = '\0';
        }
    }
    if (host[0] == '\0') return -1;

    size_t hl2 = strlen(host);
    if (hl2 >= sizeof(cfg->broker_host)) return -1;
    memcpy(cfg->broker_host, host, hl2);
    cfg->broker_host[hl2] = '\0';
    cfg->broker_port = port;
    size_t idlen2 = strlen(tunnel_id);
    if (idlen2 >= sizeof(cfg->tunnel_id)) return -1;
    memcpy(cfg->tunnel_id, tunnel_id, idlen2);
    cfg->tunnel_id[idlen2] = '\0';
    return 0;
}

static int parse_listen(tm_peer_cfg *cfg, const char *s) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s) return -1;
    char host[256];
    size_t hl = (size_t)(colon - s);
    if (hl >= sizeof(host)) return -1;
    memcpy(host, s, hl);
    host[hl] = '\0';
    if (host[0] == '[') {
        size_t n = strlen(host);
        memmove(host, host + 1, n - 2);
        host[n - 2] = '\0';
    }
    char *end = NULL;
    long v = strtol(colon + 1, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 65535) return -1;
    size_t hl2 = strlen(host);
    if (hl2 >= sizeof(cfg->listen_host)) return -1;
    memcpy(cfg->listen_host, host, hl2);
    cfg->listen_host[hl2] = '\0';
    cfg->listen_port = (uint16_t)v;
    return 0;
}

int main(int argc, char **argv) {
    tm_ignore_sigpipe();
    if (argc < 2) {
        usage(stderr);
        return 1;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "help") == 0) {
        usage(stdout);
        return 0;
    }
    if (strcmp(argv[1], "connect") != 0 || argc < 3) {
        fprintf(stderr, "unknown command '%s'\n", argv[1]);
        usage(stderr);
        return 1;
    }

    tm_peer peer;
    memset(&peer, 0, sizeof(peer));
    peer.cfg.proto = TM_PROTO_TCP;
    peer.cfg.log_level = TM_LOG_INFO;
    peer.cfg.verify_ca = true;
    peer.cfg.handshake_timeout_ms = 10000;
    peer.cfg.idle_timeout_ms = 90000;
    peer.cfg.reconnect_delay_ms = 1000;
    peer.cfg.reconnect_max_delay_ms = 30000;
    peer.cfg.udp_flow_idle_timeout_ms = 30000;
    peer.cfg.udp_max_datagram_size = TM_DEFAULT_DATAGRAM;
    peer.cfg.udp_max_flows = 1024;

    if (parse_tunnel_url(&peer.cfg, argv[2]) != 0) {
        fprintf(stderr, "invalid tunnel address '%s'\n", argv[2]);
        return 1;
    }

    static const struct option opts[] = {
        {"token", required_argument, NULL, 't'},
        {"token-file", required_argument, NULL, 'T'},
        {"listen", required_argument, NULL, 'l'},
        {"protocol", required_argument, NULL, 'p'},
        {"ca", required_argument, NULL, 'c'},
        {"no-verify-ca", no_argument, NULL, 'n'},
        {"log-level", required_argument, NULL, 'L'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    int c;
    while ((c = getopt_long(argc - 2, argv + 2, "t:T:l:p:c:nL:h", opts, NULL))
           != -1) {
        switch (c) {
        case 't':
            snprintf(peer.cfg.token, sizeof(peer.cfg.token), "%s", optarg);
            break;
        case 'T': {
            FILE *fp = fopen(optarg, "r");
            if (!fp || !fgets(peer.cfg.token, sizeof(peer.cfg.token), fp)) {
                if (fp) fclose(fp);
                fprintf(stderr, "cannot read --token-file\n");
                return 1;
            }
            fclose(fp);
            peer.cfg.token[strcspn(peer.cfg.token, "\r\n")] = '\0';
            break;
        }
        case 'l':
            if (parse_listen(&peer.cfg, optarg) != 0) {
                fprintf(stderr, "invalid --listen address '%s'\n", optarg);
                return 1;
            }
            break;
        case 'p':
            if (strcmp(optarg, "tcp") == 0) peer.cfg.proto = TM_PROTO_TCP;
            else if (strcmp(optarg, "udp") == 0) peer.cfg.proto = TM_PROTO_UDP;
            else {
                fprintf(stderr, "invalid --protocol '%s' (tcp|udp)\n", optarg);
                return 1;
            }
            break;
        case 'c':
            snprintf(peer.cfg.ca_path, sizeof(peer.cfg.ca_path), "%s", optarg);
            break;
        case 'n':
            peer.cfg.verify_ca = false;
            break;
        case 'L':
            if (tm_log_level_parse(optarg, &peer.cfg.log_level) != 0) {
                fprintf(stderr, "invalid --log-level '%s'\n", optarg);
                return 1;
            }
            break;
        default:
            usage(stderr);
            return 1;
        }
    }
    if (peer.cfg.token[0] == '\0' || peer.cfg.listen_port == 0) {
        fprintf(stderr, "--token and --listen are required\n");
        return 1;
    }
    if (peer.cfg.proto == TM_PROTO_UDP) {
        /* in udp mode the url port is the tunnel's public udp port */
        peer.cfg.public_port = peer.cfg.broker_port;
    }

    peer.log = tm_log_new(STDERR_FILENO, "peer", peer.cfg.log_level);
    peer.loop = uv_default_loop();

    char errbuf[256];
    const char *ca = peer.cfg.ca_path[0] ? peer.cfg.ca_path : NULL;
    peer.tls_ctx = tm_tls_client_ctx(ca, peer.cfg.verify_ca,
                                     errbuf, sizeof(errbuf));
    if (!peer.tls_ctx) {
        tm_log_error(peer.log, "ssl_ctx", NULL, NULL, "%s", errbuf);
        return 1;
    }
    peer.dtls_ctx = tm_dtls_client_ctx(ca, peer.cfg.verify_ca,
                                       errbuf, sizeof(errbuf));
    if (!peer.dtls_ctx) {
        tm_log_error(peer.log, "ssl_ctx", NULL, NULL, "%s", errbuf);
        return 1;
    }

    g_peer = &peer;
    uv_signal_t sigint, sigterm;
    uv_signal_init(peer.loop, &sigint);
    sigint.data = &peer;
    uv_signal_start(&sigint, on_signal, SIGINT);
    uv_signal_init(peer.loop, &sigterm);
    sigterm.data = &peer;
    uv_signal_start(&sigterm, on_signal, SIGTERM);

    if (peer.cfg.proto == TM_PROTO_TCP) {
        if (tm_peer_tcp_listen(&peer) != 0) {
            tm_log_free(peer.log);
            return 1;
        }
    } else {
        tm_peer_udp_start(&peer);
    }

    int rc = uv_run(peer.loop, UV_RUN_DEFAULT);
    SSL_CTX_free(peer.tls_ctx);
    SSL_CTX_free(peer.dtls_ctx);
    tm_log_free(peer.log);
    return rc;
}

void tm_peer_shutdown(tm_peer *p) {
    if (p->shutting_down) return;
    p->shutting_down = true;
    if (p->listening) {
        uv_close((uv_handle_t *)&p->listener, NULL);
        p->listening = false;
    }
    if (p->cfg.proto == TM_PROTO_UDP) tm_peer_udp_stop(p);
    while (p->sessions) tm_psess_close(p, p->sessions);
    uv_stop(p->loop);
}
