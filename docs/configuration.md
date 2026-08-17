# Configuration

Three components are configured separately: the broker from a file, the API
from environment variables, and the agent/peer from a file or flags. Defaults
are chosen for a 2 vCPU / 2 GB VPS and are deliberately conservative — raise
them when you have measured that you need to.

## Broker — `/etc/tunnelmate/broker.conf`

`key = value`, one per line, `#` comments. A complete example ships as
[deployment/broker.conf](../deployment/broker.conf).

### Listeners

| Key | Default | Meaning |
|---|---|---|
| `broker.listen_host` | `0.0.0.0` | Address for the control port and every public listener. |
| `broker.control_port` | `7000` | TLS port for agent control, agent data connections and closed peers. |
| `broker.public_port_start` | `20000` | First allocatable public port. |
| `broker.public_port_end` | `40000` | Last allocatable public port, inclusive. A single-port range is legal. |

TCP and UDP port namespaces are tracked independently, so `tcp://host:25000`
and `udp://host:25000` can both exist. Keep the range unprivileged; the broker
never binds a privileged port and never lets a client choose an interface.

Closed **TCP** tunnels consume no public port at all — their consumers connect
to `control_port` — so size the range for open tunnels plus closed UDP.

### TLS and keys

| Key | Default | Meaning |
|---|---|---|
| `broker.tls_cert` | — | Certificate chain (PEM). Its SAN must match what clients dial, whether that is a hostname or a bare IP. |
| `broker.tls_key` | — | Private key (PEM), mode 0640 or stricter. |
| `broker.hmac_key_file` | `/var/lib/tunnelmate/hmac.key` | 32-byte key used to HMAC stored capabilities. Generated on first start. |

Rotating the HMAC key invalidates every stored capability, so treat it as a
planned migration rather than routine hygiene.

### Limits

| Key | Default | Meaning |
|---|---|---|
| `broker.max_tunnels` | `256` | Live tunnels. At ~5.6 KiB each this is a small memory cost; the real ceiling is the port range. |
| `broker.max_streams` | `2048` | Active TCP streams across all tunnels. |
| `broker.max_streams_per_tunnel` | `128` | Stops one tunnel starving the rest. |
| `broker.max_pending_streams` | `128` | Streams accepted but not yet bound by an agent. |
| `broker.connect_rate_per_ip` | `30` | Public connections per second per source **address** (port is ignored, or the limit would never apply). |

### Timers

| Key | Default | Meaning |
|---|---|---|
| `broker.handshake_timeout_ms` | `15000` | Deadline for completing TLS and the first frame. Bounds slowloris. |
| `broker.idle_timeout_ms` | `90000` | Silence before a control session is declared dead. |
| `broker.heartbeat_interval_ms` | `15000` | PING cadence. |
| `broker.bind_timeout_ms` | `10000` | How long a pending stream waits for its agent data connection. |
| `broker.shutdown_grace_ms` | `5000` | Time active streams get after SIGTERM before being cut. |

### UDP

| Key | Default | Meaning |
|---|---|---|
| `broker.udp_max_datagram_size` | `1400` | Maximum application payload. Larger datagrams are **dropped, never truncated**. Kept under the 1400-byte DTLS link MTU to avoid IP fragmentation. |
| `broker.udp_max_flows` | `32768` | Global flow mappings. |
| `broker.udp_max_flows_per_tunnel` | `2048` | Per-tunnel flow mappings. |
| `broker.udp_flow_idle_timeout_ms` | `30000` | Idle before a mapping is reclaimed. Raise for long-lived sessions with sparse traffic. |
| `broker.udp_max_packets_per_tunnel` | `2000` | Packets/second per tunnel. |
| `broker.udp_max_packets_per_source` | `200` | Packets/second per source. The main anti-amplification control. |
| `broker.udp_flow_creation_rate` | `50` | New flows/second per tunnel. |
| `broker.udp_queue_packets` | `256` | Bounded outbound queue depth, and the cap on outstanding sends toward a client. Overflow is dropped and counted. |

Every drop increments a counter naming its cause — see
[monitoring.md](monitoring.md). If `udp_dropped_rate_limit` climbs during
legitimate use, raise the rate limits rather than the queue.

### Logging

`broker.log_level` — `debug`, `info` (default), `warning`, `error`. `debug`
logs per-stream lifecycle events; it never logs payload bytes or credentials at
any level.

## Control plane — environment

Written to `/etc/tunnelmate/tunnelmate.env` (root:tunnelmate, 0640) by the
installer. Example: [deployment/example.env](../deployment/example.env).

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELMATE_DB` | `/var/lib/tunnelmate/control.db` | SQLite database. |
| `TUNNELMATE_BROKER_SOCKET` | `/run/tunnelmate/broker.sock` | Broker IPC socket. Must be under 108 bytes; the broker refuses to start otherwise. |
| `TUNNELMATE_PUBLIC_HOST` | `localhost` | **Appears in every `peer_address`.** Set it to what consumers will dial — a hostname or a bare IP. |
| `TUNNELMATE_BROKER_PORT` | `7000` | Advertised in closed-TCP peer addresses; must match `broker.control_port`. |
| `TUNNELMATE_API_HOST` | `127.0.0.1` | Bind address. Keep it on loopback behind a proxy. |
| `TUNNELMATE_API_PORT` | `8000` | Bind port. Change it if something else owns 8000. |
| `TUNNELMATE_SECRET_KEY` | random | Signs admin sessions. **Required, 32+ chars, in production**; a random per-start value logs everyone out on restart. |
| `TUNNELMATE_PRODUCTION` | `false` | Enforces the secret-key requirement and secure cookies. |
| `TUNNELMATE_SECURE_COOKIES` | follows production | `Secure` flag on session cookies. |
| `TUNNELMATE_DOCS_ENABLED` | `true` | Serves `/docs`, `/redoc`, `/openapi.json`. |
| `TUNNELMATE_LEASE_SECONDS` | `86400` | Default lease. |
| `TUNNELMATE_ADMIN_USERNAME` | — | Bootstrapped on start when both are set. |
| `TUNNELMATE_ADMIN_PASSWORD` | — | Minimum 12 characters. There is no default administrator. |
| `TUNNELMATE_SOURCE_URL` | upstream repository | Where `/llms.txt` tells readers to clone and `pip install` from. Point it at your fork if you run one. |
| `TUNNELMATE_BROKER_CERT` | `/etc/tunnelmate/certs/broker.crt` | Certificate served at `/v1/broker-certificate` so agents can verify a self-signed deployment. Certificate only — the endpoint refuses to serve anything containing a private key. |

### Abuse limits

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELMATE_CREATE_RATE` | `10` | Tunnel creations per minute per source IP. |
| `TUNNELMATE_MAX_TUNNELS_PER_IP` | `20` | Live tunnels per source IP. |
| `TUNNELMATE_MAX_REQUEST_BYTES` | `65536` | Refused at the middleware on `Content-Length`. |
| `TUNNELMATE_MAX_ANNOUNCEMENT_BYTES` | `16384` | Serialized announcement ceiling. |
| `TUNNELMATE_MAX_ATTRIBUTE_DEPTH` | `6` | Attribute nesting. |
| `TUNNELMATE_MAX_ATTRIBUTE_KEYS` | `128` | Attribute key count. |

### Metrics

| Variable | Default | Meaning |
|---|---|---|
| `TUNNELMATE_METRICS_INTERVAL` | `5` | Sampling cadence in seconds. |
| `TUNNELMATE_METRICS_HISTORY` | `240` | Samples retained. Interval × history is the console window; 5 × 240 is 20 minutes for a few hundred KiB. |

## Agent — config file

The SDK writes this automatically with mode 0600 and removes it on stop. Write
it yourself only when running the agent standalone. **Never pass secrets on the
command line** — other local users can read `/proc/PID/cmdline`.

```ini
agent.tunnel_id = tun_...
agent.agent_secret = ...
agent.local_host = 127.0.0.1
agent.local_port = 5675
agent.broker_host = broker.example.com
agent.broker_port = 7000
agent.broker_udp_port = 20001     # UDP tunnels: the allocated public port
agent.protocol = tcp              # tcp | udp
agent.verify_ca = true
agent.ca_path = /etc/ssl/certs/ca-certificates.crt
agent.log_level = info
```

| Key | Default | Meaning |
|---|---|---|
| `agent.verify_ca` | `true` | Certificate and hostname verification. Setting `false` is development-only and must be deliberate. |
| `agent.ca_path` | system store | CA bundle for a private CA. |
| `agent.reconnect_delay_ms` | `1000` | Initial backoff; doubles per failure with ±20% jitter. |
| `agent.reconnect_max_delay_ms` | `30000` | Backoff ceiling. |
| `agent.local_connect_timeout_ms` | `10000` | Deadline for reaching the local service. |
| `agent.udp_max_datagram_size` | `1400` | Should match the broker. |
| `agent.udp_max_flows` | `1024` | Local UDP sockets, one per active flow. |
| `agent.udp_max_packets_per_flow` | `1000` | Per-second cap per flow. |

## Peer — flags

```bash
tunnelmate-peer connect tunnel://broker.example.com:7000/tun_ID \
  --token-file ./token \
  --listen 127.0.0.1:9000 \
  --protocol tcp \
  --ca-path /etc/ssl/certs/ca-certificates.crt \
  --log-level info
```

Use `--token-file` (mode 0600), not `--token`, for the same `/proc` reason.
`--no-verify-ca` exists for development and disables certificate checking; it
should never appear in a production command line.

For closed **UDP**, the URL port is the tunnel's allocated public UDP port
rather than the control port, because the DTLS endpoint lives there.

## Changing configuration

The broker reads its file at startup. Re-running the installer restarts both
services, so configuration changes take effect; a bare `systemctl reload` does
not reload the broker config.

A broker restart drops in-flight streams — agents reconnect on their own
backoff and new connections work within seconds. An API restart affects no
traffic at all.
