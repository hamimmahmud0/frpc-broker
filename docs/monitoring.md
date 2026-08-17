# Monitoring

TunnelMate ships no monitoring stack. On a 2 GB VPS the cost of one would
exceed the service it watches, so observability is a bounded in-memory series
plus whatever you already run externally.

## Endpoints

| Endpoint | Auth | Use |
|---|---|---|
| `GET /health/live` | none | Process liveness. Checks nothing external, so it stays up when a dependency is down. |
| `GET /health/ready` | none | Readiness. Verifies SQLite **and** broker IPC; returns 503 if either is unavailable. |
| `GET /v1/status` | none | Public broker counters. |
| `GET /v1/admin/system` | admin | Current sample plus history: CPU, memory, disk, load, per-process RSS and descriptors, derived rates. |
| `GET /v1/admin/system/stream` | admin | The same samples over SSE as they are taken. `?events=N` closes after N frames. |
| `GET /v1/admin/topology` | admin | Live tunnel/announcement graph. |

Point an uptime check at `/health/ready`, not `/health/live` — liveness passes
while the broker is dead, which is exactly the case worth alerting on.

## Broker counters

Exposed through `/v1/status` and the IPC socket.

**Traffic** — `rx_bytes_total`, `tx_bytes_total`, `udp_bytes_rx`,
`udp_bytes_tx`, `datagrams_rx_total`, `datagrams_tx_total`, `conns_total`,
`streams_total`, `flows_total`.

**Live state** — `tunnel_count`, `stream_count`, `ports_used`, `uptime_ms`.

**Faults** — `failed_auths`, `protocol_errors`, `agent_reconnects`,
`conns_rate_limited`, `stream_errors`, `udp_transport_errors`.

**UDP drops, by cause** — `udp_dropped_queue_full`, `udp_dropped_oversize`,
`udp_dropped_rate_limit`, `udp_dropped_no_flow`, `udp_flow_expired`.

The drop counters are split by reason deliberately: "queue full" means the
tunnel is saturated, "rate limit" means a client exceeded policy, "oversize"
means an application is sending datagrams past the configured maximum, and
"no flow" means replies arrived for a mapping that had already expired. They
call for different responses, so they are never summed into one number.

All counters are held in broker memory and reset on restart. If you need
history beyond the console's window, scrape `/v1/status` into whatever you
already run, with a retention policy — do not let it grow on this disk.

## In-memory series

The API samples host and broker state every `TUNNELMATE_METRICS_INTERVAL`
seconds (default 5) into a ring of `TUNNELMATE_METRICS_HISTORY` samples
(default 240), giving a 20-minute window for a few hundred KiB. Nothing is
written to disk and the series is lost on restart, which is the correct trade
for a service that must never fill its own 2 GB disk.

## Console

`/admin` shows CPU, RAM, disk, load, broker and API RSS, broker descriptors,
RX/TX rates, connection rate, reconnects and protocol errors, each with an
inline sparkline over the retained window. It updates over SSE, so an open
console costs one long-lived connection rather than a poll loop. Clicking a
tunnel's stream count opens its runtime detail.

## What to alert on

| Signal | Why it matters |
|---|---|
| `/health/ready` failing | Broker IPC or SQLite is down; no new tunnels can be created. |
| Disk above 85% | SQLite and journald are the only writers, but they are enough to fill 2 GB. |
| Memory above ~80% | Bounded buffers mean this should be stable; a climb suggests a leak worth investigating. |
| `agent_reconnects` climbing steadily | Network instability, or agents being dropped for a reason worth reading the log for. |
| `failed_auths` climbing | Credential guessing, or a misconfigured agent retrying with a stale secret. |
| `protocol_errors` climbing | Malformed traffic; harmless individually, but a sustained rate is someone probing. |
| `udp_dropped_queue_full` sustained | The tunnel is saturated; raise limits or reduce the offered rate. |
| `ports_used` near the range size | Port exhaustion is imminent; new tunnels will start failing. |
| Broker restart count | Should be zero. Anything else means a crash — capture the journal. |

Idle memory is around 10 MB for the broker and 40 MB for the API, and stays
flat under load: 6 GiB transfers move the broker by well under a megabyte. A
steadily rising RSS is therefore a real signal, not noise.

## Logs

Both services log structured JSON to stderr, which systemd routes to journald.

```bash
journalctl -u tunnelmated -u tunnelmate-api -f
journalctl -u tunnelmated --since -1h -p warning
```

Cap journald so logs cannot fill the disk:

```ini
# /etc/systemd/journald.conf
SystemMaxUse=128M
```

Logs carry metadata and error codes only — never credentials, never payload
bytes, at any level. Attacker-controlled input is bounded before it reaches a
log line, so malformed traffic cannot be used to flood or forge log entries.

## Prometheus

Not built in. `/v1/status` is flat JSON and converts to the text exposition
format in a few lines if you want it; the counters above map directly to
gauges and counters.
