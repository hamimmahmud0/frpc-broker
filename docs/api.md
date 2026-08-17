# HTTP API

Base URL is wherever the control plane is published. The live OpenAPI document
is `/openapi.json`, with Swagger at `/docs` and ReDoc at `/redoc`.

There is **no global API key**. Creating a tunnel requires no account, no login
and no credential of any kind. Each tunnel instead gets its own capabilities,
returned once at creation, which authorise operations on that tunnel and
nothing else.

## Authentication

| Header | Used by |
|---|---|
| `X-Tunnel-Management-Secret` | Owner operations on one tunnel |
| `X-CSRF-Token` | Admin state-changing requests (with the session cookie) |

Failure to authenticate returns `404`, identical to a tunnel that does not
exist — the API is deliberately not an existence oracle.

## Errors

```json
{"error": {"code": "TUNNEL_NOT_FOUND", "message": "Tunnel was not found.", "request_id": "req_VkyvUsXqjCiN"}}
```

Every response carries `X-Request-ID`; supply your own via the request header
and it is echoed if it matches `req_*` and is under 80 characters. Stack traces
never appear in a response body.

| Code | Status | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 422 | Request failed schema validation. `details` names the fields. |
| `REQUEST_TOO_LARGE` | 413 | Body exceeded the configured limit. |
| `TUNNEL_NOT_FOUND` | 404 | No such tunnel, or the wrong capability. |
| `RATE_LIMITED` | 429 | Creation or login rate exceeded. |
| `BROKER_UNAVAILABLE` | 503 | Broker IPC is down. |
| `TUNNEL_CREATE_FAILED` | 503 | Broker refused, e.g. port range exhausted. |

## Tunnels

### `POST /v1/tunnels`

```bash
curl -X POST https://broker.example.com/v1/tunnels \
  -H 'Content-Type: application/json' \
  -d '{"scope": "open", "protocol": "tcp"}'
```

| Field | Required | Values |
|---|---|---|
| `scope` | yes | `open`, `closed` |
| `protocol` | no | `tcp` (default), `udp` |
| `shared_token` | no | Closed mode only; generated securely if omitted |

```json
{
  "tunnel_id": "tun_UE7u16l_zv67CsKO",
  "protocol": "tcp",
  "scope": "open",
  "peer_address": "tcp://163.61.236.112:20000",
  "public_port": 20000,
  "broker_control_port": 7000,
  "agent_secret": "IlRysefG4qdNYuBE...",
  "management_secret": "951rDXpuFGzWFWuE...",
  "expires_at": 1787037925
}
```

**The secrets are shown once and never again.** Closed tunnels also return
`shared_token`. Store them immediately; there is no recovery path, by design.

Address forms:

| Scope | Protocol | `peer_address` |
|---|---|---|
| open | tcp | `tcp://host:20000` |
| open | udp | `udp://host:20001` |
| closed | tcp | `tunnel://host:7000/tun_ID` (the control port) |
| closed | udp | `tunnel://host:20004/tun_ID` (its own UDP port) |

### `GET|PATCH|DELETE /v1/tunnels/{id}`

All require `X-Tunnel-Management-Secret`.

```bash
curl https://broker.example.com/v1/tunnels/tun_ID -H 'X-Tunnel-Management-Secret: ...'
curl -X PATCH .../v1/tunnels/tun_ID -H 'X-Tunnel-Management-Secret: ...' \
     -H 'Content-Type: application/json' -d '{"enabled": false}'
curl -X DELETE .../v1/tunnels/tun_ID -H 'X-Tunnel-Management-Secret: ...'
```

`GET` returns state without secrets: protocol, scope, peer address, enabled,
online, active streams, byte counters, created and expiry timestamps.

Deleting closes the listener, drops the agent, terminates active streams,
releases the public port and disables the tunnel's announcements. It is
idempotent — a second delete returns 404 like any unknown tunnel.

### Lease and rotation

```bash
POST /v1/tunnels/{id}/renew                 # extend by the configured lease
POST /v1/tunnels/{id}/rotate-token          # new shared token, returned once
POST /v1/tunnels/{id}/rotate-agent-secret   # new agent secret, returned once
```

All require the management secret. Rotation invalidates the previous value
immediately, so update the agent config before or alongside the call. The SDK
renews automatically while a tunnel is running.

## Announcements

### `POST /v1/announce`

```bash
curl -X POST https://broker.example.com/v1/announce \
  -H 'Content-Type: application/json' \
  -H 'X-Tunnel-Management-Secret: ...' \
  -d '{
        "tunnel_id": "tun_ID",
        "service_name": "Yolo Inference Service",
        "service_id": "yolov11-detection",
        "llms": "https://example.com/llms.txt",
        "attributes": {"version": 11, "size": "n"}
      }'
```

`llms` is required and must be a structurally valid `http(s)` URL of bounded
length. **The server never fetches it** — validation is structural only, which
removes the SSRF risk entirely.

`peer_address`, `protocol` and `scope` are derived from the tunnel, not taken
from the request, so nobody can advertise an address they do not control.

`attributes` accepts arbitrary JSON within the configured depth, key-count and
size limits. Nothing about them is TunnelMate-specific; they never affect
transport.

### Reading and searching

```bash
GET /v1/announce                  # list
GET /v1/announce/{id}             # one
GET /v1/announce/search?service=yolo&scope=open&protocol=tcp&attribute.size=n
```

Filters: `service` (substring of the name), `service_id`, `scope`, `protocol`,
`tunnel_id`, and `attribute.NAME=value` for any attribute. All parameters are
bound, never concatenated into SQL.

Results carry derived state — `online`, `last_seen`, `created_at`,
`updated_at`, `expires_at` — so an announcement attached to an offline tunnel
shows as offline rather than vanishing on a brief agent disconnect.

### `PATCH|DELETE /v1/announce/{id}`

Require the owning tunnel's management secret. Another tunnel's secret returns
403/404 and changes nothing.

## Health and status

| Endpoint | Meaning |
|---|---|
| `GET /health/live` | Process is up. Checks no dependency, so it stays 200 when the broker is down. |
| `GET /health/ready` | Checks SQLite **and** broker IPC. 503 if either is unavailable. Monitor this one. |
| `GET /v1/status` | Public broker counters. |
| `GET /llms.txt` | `text/plain; charset=utf-8` description of the service for agents and crawlers. |

## Admin

Cookie session; every state-changing request also needs `X-CSRF-Token` from the
login response.

```bash
curl -X POST .../v1/admin/login -H 'Content-Type: application/json' \
     -d '{"username": "operator", "password": "..."}' -c jar
```

```text
GET    /v1/admin/tunnels[?q=]                    list and search
GET    /v1/admin/tunnels/{id}/streams            runtime detail
PATCH  /v1/admin/tunnels/{id}                    enable/disable
DELETE /v1/admin/tunnels/{id}                    delete
POST   /v1/admin/tunnels/{id}/streams/{sid}/kill kill one stream
GET    /v1/admin/announcements[?q=]              list and search
PATCH  /v1/admin/announcements/{id}              enable/verify/edit
DELETE /v1/admin/announcements/{id}              remove
GET    /v1/admin/topology                        live graph
GET    /v1/admin/system[?history=N]              host and broker metrics
GET    /v1/admin/system/stream[?events=N]        SSE metric stream
GET|POST|DELETE /v1/admin/blocked-ips[/{cidr}]   CIDR blocklist
```

Administrative operations are recorded in an audit log holding metadata only —
never payloads, never secrets.

## Limits

Creation is rate limited per source IP and capped per source IP. Bodies,
announcement size, attribute depth and key count are all bounded — see
[configuration.md](configuration.md). Exceeding them returns 429 or 413 rather
than degrading the service for everyone else.
