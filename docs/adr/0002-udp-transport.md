# ADR-0002: UDP Data Plane — DTLS 1.2 Datagram Transport

Status: Accepted (QUIC DATAGRAM deferred; see Future work)

## Context

UDP tunnels must preserve datagram semantics, be encrypted, and traverse NAT.
The specification prefers QUIC DATAGRAM via ngtcp2/quiche/lsquic, and
explicitly allows a properly designed DTLS-based datagram transport if QUIC
DATAGRAM support proves impractical for the target platform.

## Evaluation on the target platform

The target is a minimal Ubuntu/Debian VPS (2 vCPU, 2 GB RAM, 2 GB SSD) plus the
development host. Constraints:

- ngtcp2/quiche/lsquic are **not packaged** in the available repositories;
  building them from source adds several heavyweight dependencies
  (nghttp3, BoringSSL/Quiche deps) to a system with a 2 GB disk budget.
- OpenSSL provides a mature **DTLS 1.2** implementation alongside the TLS
  dependency already required by the TCP plane. OpenSSL does not currently
  expose DTLS 1.3, so claiming it would be an unsafe protocol downgrade lie.
- DTLS adds handshake latency per tunnel, performed once per
  agent/broker tunnel session (not per datagram). Per-datagram overhead is a
  single AEAD record, comparable to QUIC DATAGRAM.

## Decision

Use **DTLS 1.2 (OpenSSL)** as the encrypted datagram transport between
agent↔broker and peer↔broker for UDP tunnels.

- One DTLS "tunnel session" per agent, shared by all flows of that tunnel.
- User UDP payloads travel as DTLS application-data records, one datagram per
  record, wrapped in the 11-byte TunnelMate envelope (flow_id + flags).
- No custom cryptography anywhere; DTLS provides AEAD encryption,
  and anti-replay protection. NAT mappings are maintained with authenticated
  traffic; transparent address rebinding is future work.
- Closed-mode peers authenticate over the DTLS session using the same
  constant-time token comparison used by TCP closed tunnels.

## Consequences

- Datagram semantics preserved (one record in → one datagram out).
- No TCP HOL blocking on the UDP path.
- Future migration to QUIC DATAGRAM is confined to the UDP transport module
  (`broker_udp.c` / `agent_udp.c`); envelope and flow model remain unchanged.

## Alternatives rejected

- UDP-over-TLS-over-TCP: head-of-line blocking changes UDP semantics (rejected
  by specification).
- Custom packet encryption: forbidden by specification.
- ngtcp2/quiche now: impractical dependency footprint for the 2 GB VPS and
  unavailable system packages; recorded as future work.
