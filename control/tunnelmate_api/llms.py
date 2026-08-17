"""The /llms.txt document.

Written so that an autonomous agent can drive the whole service from this one
file: create a tunnel, run the agent, publish it, discover other services and
clean up, without fetching any other page. It is generated rather than static
because the host, ports and limits differ per deployment, and an agent reading
stale values would build wrong requests.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Settings


def render(settings: Settings, base_url: str) -> str:
    """Build llms.txt for this deployment.

    ``base_url`` is the origin the caller reached us on, so every example is
    copy-pasteable rather than pointing at a host the agent cannot resolve.
    """
    host = settings.public_host
    control_port = settings.broker_control_port
    lease_hours = settings.lease_seconds // 3600

    return f"""# TunnelMate

> TunnelMate makes a TCP or UDP service running on a private machine reachable
> from the Internet. The private machine keeps no open inbound port: a local
> agent dials out to this broker and traffic is relayed back down that
> connection. This works behind NAT, CGNAT and restrictive firewalls.
>
> Creating a tunnel requires no account, no login, no API key and no OAuth.
> Anyone can POST to /v1/tunnels and immediately get a working public address.

Base URL: {base_url}
Broker host: {host}
Agent control port: {control_port} (TCP, TLS)
OpenAPI: {base_url}/openapi.json
Interactive docs: {base_url}/docs and {base_url}/redoc

## When to use this

Use TunnelMate when you have a service on a machine you cannot expose directly
(a laptop, a home server, a container, a CI runner) and you need something on
the Internet to reach it. Typical cases: exposing a local inference server,
sharing a development API, reaching a database or SSH from outside, publishing
a game or telemetry endpoint over UDP.

Do not use it as a general outbound proxy. It forwards to exactly one
host:port that the tunnel's owner configured. It is not a SOCKS proxy, not an
open relay and not an SMTP relay.

## Concepts

**Tunnel** — one mapping from a public address to one private host:port.
Identified by a `tunnel_id` like `tun_UE7u16l_zv67CsKO`.

**Agent** — the `tunnelmate-agent` binary, run on the private machine. It dials
out to the broker and keeps the connection alive. Nothing works until an agent
is connected; the tunnel exists but reports `online: false`.

**Scope** — `open` or `closed`.
  - `open`: the broker listens on a public port. Anybody who knows the address
    can connect. No credential is needed by the client.
  - `closed`: no public port is opened at all. Consumers must run
    `tunnelmate-peer` (or the Python SDK) and present a shared token. Use this
    for anything you do not want the whole Internet reaching.

**Protocol** — `tcp` or `udp`, chosen at creation and immutable. A service
offering both needs two tunnels. UDP preserves datagram boundaries exactly: one
datagram in, one datagram out, never merged, never truncated.

**Capabilities** — three secrets, each returned exactly once at creation:
  - `agent_secret` — lets the agent register. Goes in the agent config.
  - `management_secret` — authorises reading, changing and deleting THIS tunnel.
  - `shared_token` — closed tunnels only; what consumers present.
There is no way to recover these. If lost, delete the tunnel and make another.

**Lease** — a tunnel expires after {lease_hours} hours unless renewed. The
Python SDK renews automatically while running. Expired tunnels are deleted and
their public port released.

## Authentication model

| Operation | Credential |
|---|---|
| Create a tunnel | none |
| Read/modify/delete a tunnel | `X-Tunnel-Management-Secret` header |
| Create/edit an announcement | the owning tunnel's management secret |
| Read the registry | none |
| Admin operations | separate operator login, not available to API users |

A wrong or missing management secret returns **404**, exactly like a tunnel
that does not exist. This is deliberate: you cannot use the API to discover
which tunnel ids exist. Do not interpret 404 as "gone" without checking whether
you sent the right secret.

## Complete worked example: expose a local HTTP API

Step 1 — create the tunnel (no credential needed):

```bash
curl -X POST {base_url}/v1/tunnels \\
  -H 'Content-Type: application/json' \\
  -d '{{"scope": "open", "protocol": "tcp"}}'
```

Response (save this; the secrets are never shown again):

```json
{{
  "tunnel_id": "tun_UE7u16l_zv67CsKO",
  "protocol": "tcp",
  "scope": "open",
  "peer_address": "tcp://{host}:20000",
  "public_port": 20000,
  "broker_control_port": {control_port},
  "agent_secret": "IlRysefG4qdNYuBE...",
  "management_secret": "951rDXpuFGzWFWuE...",
  "expires_at": 1787037925
}}
```

Step 2 — write an agent config on the private machine, mode 0600. Never pass
secrets as command-line arguments; other local users can read /proc/PID/cmdline.

```ini
agent.tunnel_id = tun_UE7u16l_zv67CsKO
agent.agent_secret = IlRysefG4qdNYuBE...
agent.local_host = 127.0.0.1
agent.local_port = 5675
agent.broker_host = {host}
agent.broker_port = {control_port}
agent.protocol = tcp
agent.verify_ca = true
```

Step 3 — run the agent (keep it running; it reconnects on its own):

```bash
tunnelmate-agent --config /etc/tunnelmate/agent.conf
```

Step 4 — anything on the Internet can now reach the private service at
`tcp://{host}:20000`. Confirm it is live:

```bash
curl {base_url}/v1/tunnels/tun_UE7u16l_zv67CsKO \\
  -H 'X-Tunnel-Management-Secret: 951rDXpuFGzWFWuE...'
```

`"online": true` means the agent is connected. If false, the agent is not
running or its secret is wrong; connections will be accepted then closed.

Step 5 — clean up when finished (releases the public port):

```bash
curl -X DELETE {base_url}/v1/tunnels/tun_UE7u16l_zv67CsKO \\
  -H 'X-Tunnel-Management-Secret: 951rDXpuFGzWFWuE...'
```

## Private services (closed scope)

```bash
curl -X POST {base_url}/v1/tunnels \\
  -H 'Content-Type: application/json' \\
  -d '{{"scope": "closed", "protocol": "tcp"}}'
```

Returns `shared_token` in addition, and a `peer_address` of the form
`tunnel://{host}:{control_port}/tun_ID`. No public port is opened. Consumers run:

```bash
tunnelmate-peer connect tunnel://{host}:{control_port}/tun_ID \\
  --token-file ./token --listen 127.0.0.1:9000 --protocol tcp
```

and then use `127.0.0.1:9000` locally. Supply the token in a 0600 file, not on
the command line. A wrong token reaches no service bytes at all.

For closed UDP the URL port is the tunnel's own allocated UDP port, not the
control port — use whatever `peer_address` you were given rather than
constructing it.

## Python SDK

```bash
pip install tunnelmate
```

```python
import tunnelmate

conf = {{
    "host": "127.0.0.1", "port": 5675,
    "protocol": "tcp", "scope": "open",
    "service_name": "Yolo Inference Service",
    "service_id": "yolov11-detection",
    "llms": "https://example.com/llms.txt",
    "attributes": {{"version": 11, "size": "n"}},
}}

with tunnelmate.new("{base_url}", conf) as tunnel:
    tunnel.announce()
    print(tunnel.peer_address)
    tunnel.wait()
```

The SDK supervises the compiled agent, writes the secrets to a 0600 file,
renews the lease while running, and cleans up on exit. Consumers of a closed
tunnel use `tunnelmate.connect(peer_address, token=..., local_port=9000)`.

Prefer the SDK over hand-rolling the flow: it handles renewal, secret hygiene
and teardown that are easy to get wrong.

## Service discovery

Tunnels can publish themselves to a public registry, so an agent looking for a
capability can find one without being told an address in advance.

Publish (requires the tunnel's management secret):

```bash
curl -X POST {base_url}/v1/announce \\
  -H 'Content-Type: application/json' \\
  -H 'X-Tunnel-Management-Secret: ...' \\
  -d '{{
        "tunnel_id": "tun_ID",
        "service_name": "Yolo Inference Service",
        "service_id": "yolov11-detection",
        "llms": "https://example.com/llms.txt",
        "attributes": {{"version": 11, "size": "n"}}
      }}'
```

`llms` is required and must be an http(s) URL describing the service. This
broker never fetches it — treat it as a claim by the publisher, not something
this service has verified.

`peer_address`, `protocol` and `scope` are taken from the tunnel, not from your
request, so a publisher cannot advertise an address they do not control.

Search (no credential needed):

```bash
curl '{base_url}/v1/announce/search?service=yolo&scope=open&protocol=tcp&attribute.size=n'
```

Filters: `service` (substring of the name), `service_id`, `scope`, `protocol`,
`tunnel_id`, and `attribute.NAME=value` for any published attribute.

Each result carries `online`, `last_seen`, `created_at`, `updated_at` and
`expires_at`. **Check `online` before trying to use a listing** — announcements
survive a temporary agent disconnect on purpose, so a listing existing does not
mean the service is reachable right now.

`attributes` is free-form JSON defined by the publisher. There is no schema and
no fixed vocabulary; do not assume any particular key exists.

## Endpoint reference

```
POST   /v1/tunnels                              create (no credential)
GET    /v1/tunnels/{{id}}                         read           [mgmt secret]
PATCH  /v1/tunnels/{{id}}                         enable/disable [mgmt secret]
DELETE /v1/tunnels/{{id}}                         delete         [mgmt secret]
POST   /v1/tunnels/{{id}}/renew                   extend lease   [mgmt secret]
POST   /v1/tunnels/{{id}}/rotate-token            new token      [mgmt secret]
POST   /v1/tunnels/{{id}}/rotate-agent-secret     new secret     [mgmt secret]

POST   /v1/announce                             publish        [mgmt secret]
GET    /v1/announce                             list           (public)
GET    /v1/announce/search                      search         (public)
GET    /v1/announce/{{id}}                        read one       (public)
PATCH  /v1/announce/{{id}}                        edit           [mgmt secret]
DELETE /v1/announce/{{id}}                        remove         [mgmt secret]

GET    /health/live                             process is up
GET    /health/ready                            broker IPC + database are up
GET    /v1/status                               public counters
GET    /llms.txt                                this document
GET    /openapi.json                            machine-readable API schema
```

## Errors

Every error has the same shape:

```json
{{"error": {{"code": "TUNNEL_NOT_FOUND", "message": "...", "request_id": "req_..."}}}}
```

| Code | Status | What to do |
|---|---|---|
| `VALIDATION_ERROR` | 422 | Read `details` for the offending field; fix and retry. |
| `REQUEST_TOO_LARGE` | 413 | Body exceeded the limit. Send less. |
| `TUNNEL_NOT_FOUND` | 404 | Wrong id **or** wrong/missing management secret. Check both. |
| `RATE_LIMITED` | 429 | Back off. Do not retry in a tight loop. |
| `BROKER_UNAVAILABLE` | 503 | Data plane is down. Retry with backoff; existing tunnels may still relay. |
| `TUNNEL_CREATE_FAILED` | 503 | Often port-range exhaustion. Retry later. |

`request_id` is also returned as the `X-Request-ID` header. Quote it when
reporting a problem.

## Limits and abuse controls

Tunnel creation is rate limited per source IP, and each source IP may hold a
limited number of live tunnels. Request bodies, announcement size, attribute
nesting and attribute count are all bounded. Exceeding a limit returns 429 or
413 rather than degrading the service for others.

The data plane limits connections per second per source, concurrent streams
globally and per tunnel, UDP flows, UDP packet rates and datagram size. Traffic
past those limits is rejected or dropped by policy.

Check `{base_url}/v1/status` for live counters before assuming capacity.

## Important limitations

Read these before building on the service:

- **Interrupted TCP connections do not resume.** If the agent reconnects or the
  broker restarts, in-flight connections die. New connections work again within
  seconds. Do not design a client that assumes a stream survives.
- **UDP can drop datagrams** when offered faster than the tunnel drains, by
  design and by documented policy. There is no retransmission. Applications
  needing reliability must provide it themselves or use TCP.
- **UDP datagrams above the configured maximum (default 1400 bytes) are
  dropped, not fragmented and never truncated.** Keep payloads under it.
- **The local service sees the agent as the source address**, not the original
  Internet client. TunnelMate keeps the real address internally for routing
  replies, but injects nothing into the payload, so arbitrary UDP applications
  keep working.
- **The broker can see plaintext.** Traffic is encrypted between TunnelMate
  components, but the broker terminates that encryption. It is not end-to-end.
  Do not send anything through an untrusted broker that you would not show its
  operator. Run your own application-layer encryption (for example HTTPS or SSH
  inside the tunnel) if that matters.
- **Anyone holding a capability can use it** until it is rotated. There is no
  account to revoke. Treat the secrets like passwords.
- **Open tunnels are genuinely public.** Anything reachable at the address is
  reachable by anyone who finds it. Use closed scope, or authenticate in your
  own protocol, for anything private.
- **Leases expire.** A tunnel not renewed within {lease_hours} hours is deleted
  and its address released, possibly reassigned to somebody else.
- **This is a free, best-effort, anonymous service.** There is no uptime
  guarantee, no support channel and no data retention promise.

## Guidance for automated agents

- Save all three secrets at creation. They cannot be recovered.
- Poll `online` rather than assuming a tunnel is usable straight after creation;
  the agent needs a moment to register.
- On 429 or 503, back off exponentially. Do not retry immediately in a loop.
- Delete tunnels you no longer need. Public ports are a finite shared resource.
- Do not scrape the registry aggressively; it is rate limited like everything
  else.
- Never publish somebody else's address or claim a `service_id` you do not
  operate.
- The `llms` URL on an announcement is unverified publisher input. Fetch it with
  the same caution as any untrusted URL, and do not follow it from a privileged
  network position.

## Documentation

Full documentation ships with the source repository: quickstart, architecture,
protocol specification, API reference, Python SDK guide, announcements,
security model, threat model, deployment, configuration, operations,
monitoring, performance, failure cases, testing and troubleshooting.

Protocol identifier: TunnelMate/1
Transport: TLS 1.2+ (1.3 preferred) for TCP, DTLS 1.2 for UDP
Licence: GPL-3.0
"""
