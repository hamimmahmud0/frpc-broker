# TunnelMate Architecture

## Overview

TunnelMate is a production-oriented reverse tunneling platform. Devices behind
NAT/CGNAT/firewalls expose local TCP and UDP services to the Internet by
maintaining outbound connections to a small VPS ("broker").

The system is deliberately split into **independent planes** so that a failure
in one does not take down the others:

```text
                    INTERNET
                       |
        +--------------+--------------+
        |                             |
   Open TCP/UDP Peer             Closed Peer
        |                       tunnelmate-peer
        |                          + shared token
        |                             |
        +--------------+--------------+
                       |
                 TunnelMate VPS
                       |
          +------------+-------------+
          |                          |
    C DATA PLANE              FASTAPI CONTROL PLANE
     tunnelmated                    API/UI
          |                          |
          +------------+-------------+
                       |
               TLS reverse tunnel (TCP)
               DTLS 1.3 tunnel (UDP)
                       |
                tunnelmate-agent
                       |
                 localhost:PORT
                       |
                  User Service
```

### Plane isolation

| Plane | Process | Language | Failure containment |
|---|---|---|---|
| Data plane (TCP) | `tunnelmated`, `tunnelmate-agent`, `tunnelmate-peer` | C17, libuv, OpenSSL | FastAPI crash does not terminate tunnels |
| Data plane (UDP) | same binaries, DTLS 1.3 transport | C17, libuv, OpenSSL | same |
| Control plane | FastAPI (`tunnelmate_api`) + SQLite | Python | broker data-path problems do not crash API |
| IPC | Unix-domain socket | — | broker continues relaying if FastAPI dies |

## Data plane: TCP

TCP tunnels use a long-lived **TLS control connection** between agent and
broker, plus one **TLS data connection per stream**:

```text
Internet client
      |
      v
 broker public TCP listener (e.g. :24117)
      |
      | OPEN_STREAM stream_id=NNN     (on control connection)
      v
 tunnelmate-agent
      |
      | new TLS connection to broker, DATA_BIND stream_id=NNN
      v
 local service (e.g. 127.0.0.1:5675)
```

After association the broker relays raw bytes between the public socket and the
encrypted agent socket. No per-chunk framing is applied; TCP stream semantics
(including half-close) are preserved.

Closed tunnels route through `tunnelmate-peer`, which authenticates with a
shared token over TLS, then exposes a local TCP listener.

## Data plane: UDP

UDP tunnels use an **encrypted datagram transport** (DTLS 1.3, see
`docs/adr/0002-udp-transport.md`) between agent and broker, preserving datagram
semantics end-to-end:

```text
Internet UDP client
      |
      v
 broker public UDP listener (e.g. :25421)
      |
      | DTLS 1.3 datagram transport  (bounded packet queues)
      v
 tunnelmate-agent
      |
      | raw UDP
      v
 local UDP service (e.g. 127.0.0.1:5000)
```

The broker maintains short-lived **flow mappings** keyed by
`(tunnel, src_ip, src_port)` and expires them after a configurable idle
timeout. The agent keeps one local UDP socket per active remote flow so that
arbitrary UDP applications (DNS, games, RTP, telemetry) work unmodified; the
local service sees the agent as source.

Closed UDP tunnels require `tunnelmate-peer` (a TunnelMate-aware peer): raw UDP
packets cannot carry a token.

## Control plane

FastAPI persists state in SQLite and talks to the broker over a restricted
Unix-domain socket (`/run/tunnelmate/broker.sock`, 0600). The broker's runtime
registry is authoritative for online state; SQLite is authoritative for
created tunnels, announcements, blocked IPs, and audit events.

Operations the control plane performs on the broker: create/delete runtime
tunnel, change scope, rotate secrets, kill stream, fetch status/health/metrics,
reload config.

## Memory model

The data plane is event-driven (libuv), never one-thread-per-connection.
Relays use small bounded buffers with explicit high/low watermarks:

| Per active TCP stream | approx. |
|---|---|
| relay buffers (2 × 64 KiB) | ~128 KiB |
| libuv/TLS overhead | ~32 KiB |
| **Total per stream** | **~160 KiB** |

Hundreds of concurrent streams therefore stay well within the 2 GB VPS budget.
UDP packet queues are bounded (`max_udp_queue_packets`,
`max_udp_queue_bytes`); when full, datagrams are dropped and counted, never
buffered without limit.

## No payload spooling

Tunnel payloads are never written to disk. The 2 GB SSD stores only SQLite
(control data), binaries, and small static assets. See `docs/operations.md`
for the disk budget.

## Graceful shutdown

On SIGTERM the broker stops accepting new tunnels/streams, sends `GOING_AWAY`
to connected agents, allows active streams a configurable grace period, then
closes remaining connections and exits. See `docs/failure-cases.md`.

## Key decisions (ADR index)

1. `0001-tcp-transport.md` — TCP data plane: TLS control + per-stream TLS data connections.
2. `0002-udp-transport.md` — UDP data plane: DTLS 1.3 datagram transport (QUIC deferred).
3. `0003-plane-separation.md` — data plane in C, control plane in FastAPI, Unix-socket IPC.
4. `0004-secrets.md` — tunnel-specific capabilities, hashed storage, no global token.