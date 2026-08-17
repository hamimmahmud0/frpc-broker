#include "broker.h"
#include "tunnelmate/cJSON.h"

/* Broker status endpoint: returns a JSON document consumed by the control
   plane over the IPC socket. */

static cJSON *tunnel_json(tm_tunnel *t) {
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "id", t->id);
    cJSON_AddStringToObject(o, "proto", t->proto == TM_PROTO_TCP ? "tcp" : "udp");
    cJSON_AddBoolToObject(o, "closed", t->closed);
    cJSON_AddBoolToObject(o, "enabled", t->enabled);
    cJSON_AddNumberToObject(o, "public_port", t->public_port);
    cJSON_AddBoolToObject(o, "agent_online", t->agent_online);
    cJSON_AddNumberToObject(o, "streams_active", t->streams_active);
    cJSON_AddNumberToObject(o, "streams_total", (double)t->streams_total);
    cJSON_AddNumberToObject(o, "rx_bytes", (double)t->rx_bytes);
    cJSON_AddNumberToObject(o, "tx_bytes", (double)t->tx_bytes);
    cJSON_AddNumberToObject(o, "datagrams_rx", (double)t->datagrams_rx);
    cJSON_AddNumberToObject(o, "datagrams_tx", (double)t->datagrams_tx);
    cJSON_AddNumberToObject(o, "udp_bytes_rx", (double)t->udp_bytes_rx);
    cJSON_AddNumberToObject(o, "udp_bytes_tx", (double)t->udp_bytes_tx);
    cJSON_AddNumberToObject(o, "last_seen_ms", (double)t->last_seen_ms);
    cJSON_AddNumberToObject(o, "expires_at_ms", (double)t->expires_at_ms);
    cJSON_AddNumberToObject(o, "conns_rejected_offline",
                            (double)t->conns_rejected_offline);
    return o;
}

char *tm_metrics_json(tm_broker *b, bool include_tunnels) {
    cJSON *o = cJSON_CreateObject();
    cJSON *now = cJSON_CreateObject();
    cJSON_AddNumberToObject(now, "uptime_ms",
                            (double)(tm_now_ms() - b->start_ms));
    cJSON_AddNumberToObject(now, "stream_count", b->stream_count);
    cJSON_AddNumberToObject(now, "streams_total", (double)b->streams_total);
    cJSON_AddNumberToObject(now, "flows_total", (double)b->flows_total);
    cJSON_AddNumberToObject(now, "tunnel_count", b->tunnel_count);
    cJSON_AddNumberToObject(now, "ports_used", b->ports_used);
    cJSON_AddNumberToObject(now, "rx_bytes_total", (double)b->rx_bytes_total);
    cJSON_AddNumberToObject(now, "tx_bytes_total", (double)b->tx_bytes_total);
    cJSON_AddNumberToObject(now, "datagrams_rx_total", (double)b->datagrams_rx_total);
    cJSON_AddNumberToObject(now, "datagrams_tx_total", (double)b->datagrams_tx_total);
    cJSON_AddNumberToObject(now, "udp_bytes_rx", (double)b->udp_bytes_rx);
    cJSON_AddNumberToObject(now, "udp_bytes_tx", (double)b->udp_bytes_tx);
    cJSON_AddNumberToObject(now, "failed_auths", (double)b->failed_auths);
    cJSON_AddNumberToObject(now, "protocol_errors", (double)b->protocol_errors);
    cJSON_AddNumberToObject(now, "agent_reconnects", (double)b->agent_reconnects);
    cJSON_AddNumberToObject(now, "conns_total", (double)b->conns_total);
    cJSON_AddNumberToObject(now, "conns_rate_limited", (double)b->conns_rate_limited);
    cJSON_AddNumberToObject(now, "udp_dropped_queue_full",
                            (double)b->udp_dropped_queue_full);
    cJSON_AddNumberToObject(now, "udp_dropped_oversize",
                            (double)b->udp_dropped_oversize);
    cJSON_AddNumberToObject(now, "udp_dropped_rate_limit",
                            (double)b->udp_dropped_rate_limit);
    cJSON_AddNumberToObject(now, "udp_dropped_no_flow",
                            (double)b->udp_dropped_no_flow);
    cJSON_AddNumberToObject(now, "udp_flow_expired", (double)b->udp_flow_expired);
    cJSON_AddNumberToObject(now, "udp_transport_errors",
                            (double)b->udp_transport_errors);
    cJSON_AddNumberToObject(now, "stream_errors", (double)b->stream_errors);
    cJSON_AddItemToObject(o, "now", now);

    if (include_tunnels) {
        cJSON *arr = cJSON_CreateArray();
        for (tm_tunnel *t = b->tunnels; t; t = t->next)
            cJSON_AddItemToArray(arr, tunnel_json(t));
        cJSON_AddItemToObject(o, "tunnels", arr);
    }
    char *s = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    return s;
}

void tm_metrics_start(tm_broker *b) { (void)b; }