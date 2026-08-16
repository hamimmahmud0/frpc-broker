# ADR-0004: Anonymous Creation with Tunnel-Scoped Capabilities

Status: Accepted

## Context

Tunnel creation must require no account, login, API key, or global token.
Yet strangers must not be able to modify or delete another person's tunnel,
and the service must survive abuse.

## Decision

- `POST /v1/tunnels` is anonymous and rate-limited per source IP
  (`creation_rate_per_ip`, `max_tunnels_per_ip`).
- Every tunnel is born with random capabilities generated with
  `getrandom()`/`RAND_bytes`:
  - `agent_secret` — presented by `tunnelmate-agent` on the TLS control and
    data connections.
  - `management_secret` — presented via `X-Tunnel-Management-Secret` header
    to PATCH/DELETE/rotate/announce operations.
  - `shared_token` (closed tunnels) — presented by `tunnelmate-peer`.
- The API returns these secrets **once** in the creation response. The broker
  stores only HMAC-SHA256 digests (keyed with a broker-only key) of
  `agent_secret` and `shared_token`; the control plane stores the
  `management_secret` digest (SHA-256 with per-record salt) and, for closed
  tunnels, a salted hash of the `shared_token`.
- All secret comparisons in C use `CRYPTO_memcmp` (constant time).

## Consequences

- No global credential to leak; each tunnel is an independent capability.
- A lost `management_secret` is unrecoverable (by design).
- Rate limits bound anonymous abuse; blocked IP/CIDR lists exist for
  persistent offenders.

## Alternatives rejected

- Global API token: rejected by specification.
- Plaintext secret storage: leaks on DB compromise.
- Recovering management secrets: weakens the capability model.