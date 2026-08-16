# ADR-0003: Plane Separation and Broker↔FastAPI IPC

Status: Accepted

## Context

A FastAPI crash must not terminate existing tunnel traffic; a tunnel
data-path problem must not crash the API.

## Decision

- `tunnelmated` (C/libuv) is the only process that touches tunnel payloads.
- FastAPI (`tunnelmate_api`) runs as a separate systemd service and
  communicates with the broker over a **Unix-domain socket**:
  `/run/tunnelmate/broker.sock`, mode 0600, owned by the broker's service
  user.
- The IPC protocol is newline-delimited JSON request/response with
  `req_`-prefixed correlation ids. The broker never blocks its event loop on
  IPC: it processes requests via `uv_poll` on the socket and replies asynchronously.
- SQLite is written by FastAPI only. The broker keeps no persistent state
  beyond runtime registries and metric counters.

## Consequences

- Existing tunnels continue forwarding while FastAPI is down.
- Broker restart requires FastAPI to re-sync runtime state (it does so
  automatically by pushing its tunnel table).
- IPC must be treated as trusted (0600, same host), but is still
  size-bounded and schema-validated.

## Alternatives rejected

- Embedding the API in the broker process: violates isolation requirement.
- HTTP loopback for IPC: heavier, no permission-granular control, TLS needed.