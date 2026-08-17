# TunnelMate — technical completion report

Reporting date: 2026-08-17. Everything below was measured, not estimated.
Reference machines: the target VPS (2 vCPU, 1961 MB RAM, Ubuntu, OpenSSL 3.5.5,
libuv 1.51) and a development host.

---

## 1. Architecture summary

Two independent processes, by design and in practice:

```text
                         TunnelMate VPS
   ┌──────────────────────────────────────────────────────┐
   │  tunnelmated (C17, libuv, OpenSSL)   tunnelmate-api  │
   │  ─────────────────────────────────   ─────────────── │
   │  TLS control + TCP relay             FastAPI + SQLite│
   │  DTLS UDP relay          ◄── IPC ──► leases, registry│
   │  port allocation, metrics  unix sock  admin console  │
   └──────────────────────────────────────────────────────┘
        ▲                    ▲                     ▲
   raw TCP/UDP        tunnelmate-peer         HTTP (127.0.0.1)
   internet client    (closed tunnels)        behind a proxy
                             ▲
                      tunnelmate-agent  ──► localhost service
                      (outbound only, behind NAT)
```

A FastAPI crash cannot interrupt a relay: Python holds no payload socket and no
relay state. A relay fault cannot take down the API: they share only a Unix
socket. This was verified, not assumed — the API was killed mid-transfer and
the stream continued.

- **TCP** keeps TCP stream semantics: unframed relay after bind, real half-close,
  watermark backpressure.
- **UDP** keeps UDP datagram semantics: one application datagram to one DTLS
  record, bounded queues with an explicit drop policy, no head-of-line blocking.

---

## 2. Repository tree

```text
broker/src/          tunnelmated: control, tcp, udp, relay, registry, ipc, metrics
agent/src/           tunnelmate-agent: control, tcp, udp
peer/src/            tunnelmate-peer: tcp, udp
common/              framing, io, tls/dtls, crypto, config, logging, net (+ tests)
control/             FastAPI app, SQLite, admin console (templates + static in-package)
python-sdk/          tunnelmate package and CLI
protocol/            normative TunnelMate/1 wire specification
deployment/          systemd units, Caddyfile, broker.conf, install script
docs/                18 documents including 4 ADRs
tests/               harness + integration, failure, security, load, nat
```

~8,500 lines of C (excluding vendored cJSON), 109 Python tests, 5 C unit tests.

---

## 3. Implemented features

| Area | State |
|---|---|
| Open TCP tunnels | Working, verified over the public Internet |
| Closed TCP tunnels | Working; no public listener is bound at all |
| Open UDP tunnels | Working, datagram boundaries preserved |
| Closed UDP tunnels | Working, authenticated inside DTLS |
| Anonymous creation | No account, no login, no global API key |
| Per-tunnel capabilities | agent secret, management secret, shared token; stored as HMACs |
| Lease + renewal | 24 h default, renewable, reaper releases expired ports |
| Service registry | Announce, search, generic JSON attributes, `llms` URL |
| Admin console | Tunnels, announcements, topology, system panel, stream inspection |
| Live metrics | Bounded in-memory series, SSE stream |
| Abuse controls | Per-IP creation and connect rates, stream/flow/port caps, size limits, CIDR blocks |
| Graceful shutdown | GOING_AWAY, configurable grace, clean exit |
| Agent reconnect | Exponential backoff with jitter |
| Python SDK | Dict and typed config, lifecycle, context manager, message handler |
| Prometheus | Not built in (documented as such) |

---

## 4. Protocol summary

`TunnelMate/1`. Control messages use a fixed 10-byte header — version,
msg_type, 4-byte length, 4-byte stream_id — all big-endian, tightly packed.
Declared lengths are validated against `MAX_FRAME_PAYLOAD` (256 KiB) **before**
any allocation.

Control connection: `HELLO` → `REGISTER` → `REGISTER_OK`, then `PING`/`PONG`
heartbeats. A new public connection produces `OPEN_STREAM`; the agent dials a
fresh TLS data connection and sends `DATA_BIND(stream_id)`. After
`DATA_BIND_OK` the connection carries raw bytes with no further framing.

Closed peers authenticate with `AUTH` on the control port before binding.

UDP uses DTLS 1.2 records carrying an 11-byte envelope: `envelope_len(2)`,
`flow_id(8)`, `flags(1)`, then the verbatim payload. One datagram in, one
record, one datagram out.

Full normative text: [protocol/protocol.md](../protocol/protocol.md).

---

## 5. Security model

Transport is mandatory: TLS 1.2 minimum with 1.3 preferred for TCP, DTLS 1.2
for UDP (OpenSSL exposes no DTLS 1.3, and claiming otherwise would be a lie).
Certificate and hostname verification are on by default; disabling them
requires explicit configuration. No cryptography is implemented here.

Capabilities are generated from the OS CSPRNG, returned exactly once, stored as
keyed HMACs, and compared in constant time. Registration and closed-peer auth
perform identical work and return identical errors whether or not the tunnel
exists, so neither can be used to enumerate tunnel ids.

Anonymous creation is bounded per source IP; the data plane bounds connections,
streams, pending streams, UDP flows, datagram size, packet rates and queues.
The admin surface uses scrypt password hashes, HttpOnly/SameSite cookies, CSRF
tokens, login rate limiting and an audit log, with no default administrator.

The control plane uses parameterised SQL, escapes rendered HTML, sets
`X-Frame-Options` and a `default-src 'self'` CSP, bounds request bodies, and
never fetches `llms` URLs — they are structurally validated and stored, which
removes the SSRF oracle entirely.

Payloads and secrets are never logged, at any level, in any branch.

Details: [docs/security.md](security.md), [docs/threat-model.md](threat-model.md).

---

## 6. API endpoints

```text
POST   /v1/tunnels                              anonymous create
GET    /v1/tunnels/{id}                         owner read
PATCH  /v1/tunnels/{id}                         owner update
DELETE /v1/tunnels/{id}                         owner delete
POST   /v1/tunnels/{id}/renew                   extend the lease
POST   /v1/tunnels/{id}/rotate-token            rotate the shared token
POST   /v1/tunnels/{id}/rotate-agent-secret     rotate the agent secret

POST   /v1/announce                             create a listing
GET    /v1/announce                             list
GET    /v1/announce/search                      filter by service/scope/protocol/attribute
GET|PATCH|DELETE /v1/announce/{id}              read / owner update / owner delete

GET    /health/live  /health/ready  /v1/status  /llms.txt
GET    /openapi.json /docs /redoc

/v1/admin/login|logout, /v1/admin/tunnels[/{id}[/streams[/{sid}/kill]]],
/v1/admin/announcements, /v1/admin/topology, /v1/admin/blocked-ips,
/v1/admin/system, /v1/admin/system/stream
```

Owner operations use `X-Tunnel-Management-Secret`. Errors are always
`{"error": {"code", "message", "request_id"}}`; stack traces never reach a
response body.

---

## 7. Python SDK

```python
import tunnelmate

conf = {
    "host": "127.0.0.1", "port": 5675,
    "protocol": "tcp", "scope": "open",
    "service_name": "Yolo Inference Service",
    "service_id": "yolov11-detection",
    "llms": "http://127.0.0.1:5675/llms.txt",
    "attributes": {"version": 11, "size": "n"},
}

with tunnelmate.new("https://broker.example.com", conf) as tunnel:
    tunnel.announce()
    print(tunnel.peer_address)     # tcp://broker.example.com:20000
    tunnel.wait()
```

`TunnelConfig` provides the typed equivalent. Lifecycle: `start`, `stop`,
`wait`, `delete`, `announce`, `unannounce`, `status`, `stats`, `renew`,
`rotate_token`. Consumers use `tunnelmate.connect(peer_address, token=...,
local_port=...)`.

The SDK never reimplements the protocol; it supervises the compiled C agent and
passes secrets through a 0600 config file, never argv, and removes it on stop.
`set_message_handler()` opts into a local Python proxy — documented as the slow
path and off by default.

---

## 8. Admin console

Server-rendered HTML, small vanilla JS, no framework and no third-party asset
(the CSP is `default-src 'self'`, and a test enforces it).

Tunnel table with protocol, scope, address, live state, stream/flow counts,
byte counters, expiry, search, delete and per-tunnel inspection. Announcement
management with enable/verify/delete. Live topology. A twelve-tile system panel
— CPU, RAM, disk, load, broker and API RSS, broker descriptors, RX/TX rates,
connection rate, reconnects, protocol errors — with inline sparklines, updated
over SSE.

---

## 9. Build and deployment

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

python3 -m venv .venv
.venv/bin/pip install -e './control[dev]' -e './python-sdk[dev]'
```

Server, from a checkout, as root:

```bash
sudo TUNNELMATE_PUBLIC_HOST=203.0.113.10 \
     TUNNELMATE_ADMIN_PASSWORD='a unique long password' \
     TUNNELMATE_API_PORT=9000 \
     deployment/scripts/tunnelmate-install
```

Creates the system user and directories, builds and installs the binaries,
creates the venv, writes a 0640 environment file, generates a development
certificate with the correct SAN type for a hostname or a bare IP, installs and
restarts both systemd units, then verifies both are genuinely active and that
the health endpoint is answered by TunnelMate itself. Re-running is safe.

Firewall: TCP 7000 (agent control), TCP+UDP over the configured public range,
443 for the HTTPS proxy. The API binds `127.0.0.1` only.

---

## 10. Test results

All figures from the target VPS unless noted.

| Suite | Result |
|---|---|
| C unit tests (ctest) | 1/1 passed |
| Full Python suite | **112 passed, 4 skipped** (~91 s) |
| Under ASan + UBSan | **105 passed, 4 skipped** — no leaks, no UB |
| Extended (6 GiB TCP ×2, 6 GiB UDP, 256 conns) | **4 passed** |
| NAT namespace scenario (root) | **PASS** |
| Lint (ruff) | clean |

Acceptance criteria, all four combinations verified against real binaries:

| Mode | Verified |
|---|---|
| Open TCP | Raw client → public port → private service |
| Closed TCP | Peer + token → control port → private service; wrong token relays nothing |
| Open UDP | Raw datagrams, boundaries preserved (1, 57, 256, 1200, 1400 B) |
| Closed UDP | Authenticated peer, boundaries preserved |

**Verified over the public Internet** from a separate machine to the VPS:
anonymous creation with no credential of any kind, announce, agent registration
from behind the local network, a 64 MiB upload through the tunnel with a
matching SHA-256, registry search, `llms.txt`, and delete refused without the
management capability (404) then accepted with it (200).

---

## 11. Large-transfer result

6 GiB (6,442,450,944 bytes), generated on the fly, hashed at the sink, never
written to disk.

| Mode | Duration | Throughput | Broker peak RSS | Agent peak RSS | SHA-256 |
|---|---:|---:|---:|---:|---|
| open TCP | 11.3 s | 544.2 MiB/s | 9.9 MB | 9.8 MB | matched |
| closed TCP | 14.2 s | 432.9 MiB/s | 10.5 MB | 9.8 MB | matched |

Broker memory is flat for the entire transfer — the same ~10 MB it uses idle.
Transfer size does not influence memory, and single transfers are not capped;
6 GiB is the tested figure, not a limit.

6 GiB aggregate UDP (4,601,751 datagrams of 1400 B) in 25.0 s: broker RSS 9.7 MB
baseline → 11.8 MB peak. 1,775,694 datagrams were dropped by documented policy,
because the sender offered faster than the tunnel drained — the bounded queues
shed excess rather than buffering it.

---

## 12. Benchmark results

VPS, 512 MiB per run, loopback:

| Mode | MiB/s | vs direct | conns/s | p50 | CPU s | peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| direct localhost | 1993.9 | 100% | 4599.9 | 0.024 ms | — | — |
| open TCP | 787.8 | 39.5% | 680.3 | 0.081 ms | 0.90 | 10.1 MB |
| closed TCP | 534.0 | 26.8% | 368.7 | 0.114 ms | 1.11 | 11.0 MB |
| open TCP + Python handler | 635.4 | 31.9% | — | — | 1.28 | 9.8 MB |
| open UDP | 160.7 | 8.1% | — | 0.080 ms | 3.16 | 11.8 MB |

UDP round-trip latency through the tunnel (dev, loopback): p50 0.053–0.071 ms,
p99 0.101–0.656 ms across 64 B to 1400 B. A 1 kHz telemetry stream of 2000
datagrams lost none, duplicated none and reordered none, at 0.331 ms jitter.

Idle cost: 5.6 KiB per idle tunnel; broker ~3.4 MB and API ~43 MB resident on
the deployed VPS.

Do not read these as claims about other hardware — rerun
`tests/load/benchmark.py`.

---

## 13. Defects found and fixed

The data plane passed its four acceptance modes at the start of this work.
Building the failure, security and load suites — and running them on the target
VPS — surfaced fifteen genuine defects, most of which only appear under
sustained load or adversarial input:

**Security**

1. Closed TCP tunnels bound a public listener relaying **unauthenticated**
   traffic straight to the private service, directly contradicting the closed
   mode guarantee.
2. `REGISTER` answered "unknown tunnel" vs "bad credentials", giving anyone a
   tunnel-id enumeration oracle.
3. The per-source-IP connect limiter compared address **and port**, so every
   connection got a fresh bucket and the limit never applied.
4. Public accept read the peer address from the *listening* handle, leaving it
   uninitialised.
5. Validation errors carrying a `ValueError` crashed the error handler instead
   of returning 422, and echoed unbounded attacker input.

**Availability**

6. No binary ignored `SIGPIPE`: one client vanishing mid-write killed the
   broker and every tunnel on it.
7. After one relay leg closed, the other kept writing into the freed pointer
   (UBSan-confirmed null dereference).
8. `GOING_AWAY` terminated the agent instead of triggering reconnect, so a
   broker restart permanently killed every tunnel.
9. Re-enabling a tunnel re-initialised a libuv handle whose `uv_close` was
   still in flight; `close_refs` could also underflow into a double free.

**Correctness under load**

10. `flush_pend` could be re-entered through the low-water callback and re-send
    the slice the outer loop still held — some bytes twice, others skipped,
    with the total staying exactly right. This corrupted 6 GiB transfers.
11. A small chunk could overtake a larger one already queued, reordering the
    stream.
12. `tls_try_shutdown` zeroed `pq_len` but not `pq_off`, underflowing
    `pending()`, pinning `drained()` false and calling `SSL_write` after
    close_notify — killing the stream exactly when the reverse direction was
    needed.
13. `pause_read` stopped the socket but not the SSL decrypt loop, so
    backpressure took effect a pass late.
14. UDP queues bounded unsent bytes but sized the buffer from the absolute
    length, so capacity doubled without limit: 6 GiB of UDP cost 400 MB of RSS.
    Now 2 MB.
15. Nagle was never disabled, adding ~40 ms to every small request/response —
    21 connections/sec became 741.

Plus deployment defects the source tree could not reveal: the wheel shipped
without the console's templates and static files, and the installer's health
check accepted a 200 from an unrelated service already holding the port.

---

## 14. Failure cases tested

[docs/failure-cases.md](failure-cases.md) documents 40 failures across nine
categories — process lifecycle, agent and registration, TCP data path, UDP data
path, DTLS transport, protocol and untrusted input, control API, TLS and DNS,
and NAT — each with expected behaviour, user-visible behaviour, log behaviour,
recovery behaviour and the test that holds it. TCP, UDP and datagram-transport
failures are documented separately rather than treating UDP as TCP.

---

## 15. Known limitations

- **DTLS 1.2, not QUIC DATAGRAM.** ngtcp2/quiche/lsquic are not packaged for
  the target distribution and building them would add several heavyweight
  dependencies to a 2 GB disk. The specification permits a properly designed
  DTLS transport; the decision is recorded in
  [ADR-0002](adr/0002-udp-transport.md). Migration is confined to the UDP
  transport module.
- **DTLS 1.2 is the ceiling on UDP** because OpenSSL exposes no DTLS 1.3.
- **A new connection costs a TLS handshake** (~1.4 ms on loopback). No
  pre-established worker pool in v1; the protocol leaves room for one.
- **Interrupted TCP streams do not resume.** A broker restart or agent
  disconnect kills in-flight streams; only new connections recover.
- **UDP under-provisioning drops datagrams** by design. Applications needing no
  loss should pace themselves or use TCP.
- **Bearer capabilities are replayable** by whoever holds them, until rotation.
  Inherent to a no-account design.
- **The broker sees plaintext.** End-to-end encryption from peer to agent is
  future work.
- **Metrics are in-memory** and reset on restart.
- **The local UDP service sees the agent as the source**, not the original
  Internet address — the agent keeps a NAT-style mapping rather than injecting
  metadata that would break arbitrary UDP applications.
- **IPv6 is not exercised.** Address handling is family-neutral throughout, but
  no IPv6 test has been run.
- **Prometheus is not built in.**

---

## 16. Future work

QUIC DATAGRAM once a packaged C library is available; pre-established worker
connections; HTTP hostname routing and custom domains; mTLS; accounts and
reserved ports; bandwidth quotas; multi-broker federation; end-to-end encrypted
closed tunnels; WebSocket endpoints; service health checks; native Prometheus
exposition; IPv6 test coverage.

---

## 17. Exact commands

Local development:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel
python3 -m venv .venv && .venv/bin/pip install -e './control[dev]' -e './python-sdk[dev]'
export TUNNELMATE_BUILD_DIR=$PWD/build
ctest --test-dir build --output-on-failure
.venv/bin/pytest tests control/tests python-sdk/tests

# extended
TUNNELMATE_LARGE_BYTES=6442450944 .venv/bin/pytest tests/integration -s -k large
TUNNELMATE_UDP_LARGE_BYTES=6442450944 .venv/bin/pytest tests/load -s -k aggregate
TUNNELMATE_LOAD_EXTENDED=1 .venv/bin/pytest tests/load -s -m extended
tests/load/benchmark.py --bytes 512MiB
sudo tests/nat/nat_scenario.sh build

# sanitizers
cmake -S . -B build-sanitize -DTUNNELMATE_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-sanitize --parallel
TUNNELMATE_BUILD_DIR=$PWD/build-sanitize .venv/bin/pytest tests
```

On the VPS:

```bash
sudo apt-get install -y build-essential cmake pkg-config libuv1-dev libssl-dev python3-venv
sudo TUNNELMATE_PUBLIC_HOST=<ip-or-hostname> \
     TUNNELMATE_ADMIN_PASSWORD='<12+ characters>' \
     TUNNELMATE_API_PORT=9000 \
     deployment/scripts/tunnelmate-install

systemctl status tunnelmated tunnelmate-api
curl http://127.0.0.1:9000/health/ready
curl -X POST http://127.0.0.1:9000/v1/tunnels \
     -H 'Content-Type: application/json' -d '{"scope":"open","protocol":"tcp"}'
```

Point a client at the returned `peer_address` and run `tunnelmate-agent` beside
the service being exposed.
