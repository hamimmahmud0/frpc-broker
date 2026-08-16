# PROJECT: TunnelMate

You are a senior distributed-systems, networking, C, Python, Linux, security, and DevOps engineer.

Your task is to **design, implement, test, document, and package a production-oriented reverse TCP tunneling platform called `TunnelMate`**.

Do not stop at architecture documents or scaffolding. Build the working system.

The system is intended to run on a very small VPS:

* 2 vCPU
* 2 GB RAM
* 2 GB SSD
* Linux
* Public IPv4/IPv6 when available

The VPS allows devices behind NAT/CGNAT/firewalls to expose local TCP services to the Internet by maintaining outbound connections to the VPS.

The service itself is free and public.

There is **no account requirement and no global API token/API key required to create a tunnel**.

---

# 1. PRIMARY DESIGN PRINCIPLE

Use separate planes:

```text
                    INTERNET
                       |
        +--------------+--------------+
        |                             |
   Open TCP Peer                 Closed Peer
        |                      tunnelmate connect
        |                        + shared token
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
              TLS reverse tunnel
                       |
                tunnelmate-agent
                       |
                 localhost:PORT
                       |
                  User Service
```

The data plane and control plane MUST be independent processes.

A FastAPI crash must not terminate existing tunnel traffic.

A tunnel data-path problem must not crash the FastAPI API/UI.

---

# 2. IMPORTANT DEFAULT ASSUMPTIONS

Unless subsequently overridden, implement these decisions.

## Tunnel transport

TCP only for v1.

Use a custom lightweight reverse-tunneling protocol.

Do NOT invent cryptographic algorithms.

Use:

* C17
* libuv for asynchronous networking/event loops
* OpenSSL for TLS
* CMake
* pthreads only where useful

Use TLS 1.3 where available.

Do not transmit tunnel credentials outside encrypted transport.

---

# 3. COMPONENTS

Build this monorepo:

```text
tunnelmate/
├── broker/
│   ├── src/
│   ├── include/
│   ├── tests/
│   └── CMakeLists.txt
│
├── agent/
│   ├── src/
│   ├── include/
│   ├── tests/
│   └── CMakeLists.txt
│
├── peer/
│   ├── src/
│   ├── include/
│   ├── tests/
│   └── CMakeLists.txt
│
├── control/
│   ├── tunnelmate_api/
│   ├── templates/
│   ├── static/
│   ├── tests/
│   └── pyproject.toml
│
├── python-sdk/
│   ├── tunnelmate/
│   ├── tests/
│   ├── examples/
│   └── pyproject.toml
│
├── protocol/
│   └── protocol specification
│
├── deployment/
│   ├── systemd/
│   ├── nginx-or-caddy/
│   ├── scripts/
│   └── example.env
│
├── docs/
├── tests/
│   ├── integration/
│   ├── load/
│   ├── failure/
│   └── security/
│
├── CMakeLists.txt
├── README.md
└── LICENSE
```

Core binaries:

```text
tunnelmated
tunnelmate-agent
tunnelmate-peer
```

---

# 4. DO NOT USE FRP AS THE CORE BINARY

You may study architectural patterns from FRP, rathole, SSH reverse tunnels, ngrok-like systems, etc.

However, because the primary tunnel data plane is required to be compiled in C, implement the production data plane yourself in C.

Do NOT implement custom cryptography.

Use audited TLS/crypto libraries.

---

# 5. REVERSE-TUNNEL PROTOCOL

Favor simplicity over unnecessary custom multiplexing.

For v1 implement this model:

## Long-lived control connection

`tunnelmate-agent` opens an outbound TLS connection to `tunnelmated`.

It authenticates a specific tunnel using its generated tunnel/agent credential.

The connection remains alive with heartbeat/ping messages.

Example:

```text
agent
  |
  | TLS
  |
  +---- REGISTER tunnel
  |
  <---- REGISTER_OK
  |
  <---- OPEN_STREAM stream_id=82
```

## Data connections

When an Internet client connects to an open tunnel:

```text
Internet client
      |
      v
 tunnelmated
      |
      | OPEN_STREAM #82
      v
 control connection
      |
      v
 tunnelmate-agent
```

The agent then establishes a new TLS data connection:

```text
agent ------ TLS ------> broker
        stream_id=82
```

The broker associates that data connection with the waiting public TCP socket.

After association:

```text
public socket <---- relay ----> encrypted agent socket
```

Relay raw stream bytes.

Do not frame every payload chunk unnecessarily.

This avoids a complex multiplexed protocol in v1.

Design the protocol so multiplexing or pre-established worker connections can be introduced later without breaking compatibility.

---

# 6. PROTOCOL VERSIONING

Create an explicit protocol specification.

Example protocol identifier:

```text
TunnelMate/1
```

Include a version negotiation field.

Define message types such as:

```text
HELLO
HELLO_ACK

REGISTER
REGISTER_OK
REGISTER_ERROR

PING
PONG

OPEN_STREAM
OPEN_STREAM_ACK
OPEN_STREAM_ERROR

DATA_BIND
DATA_BIND_OK

CLOSE_STREAM

GOING_AWAY

ERROR
```

Use a compact binary header.

All integer fields crossing the network must use defined byte order.

Every variable-length payload must have a strict maximum size.

Reject malformed lengths before allocation.

Implement fuzzable parsers.

Never trust client-controlled length values.

---

# 7. OPEN TUNNEL MODE

An open tunnel is reachable directly from the Internet.

Example:

```text
tcp://tunnel.example.com:24317
```

No peer authentication is required.

Flow:

```text
Internet Client
     |
     v
broker_public_port
     |
     v
TunnelMate broker
     |
     | encrypted TunnelMate connection
     v
NAT client
     |
     v
localhost:5675
```

The API should allocate the external port automatically.

Make the allowed public port range configurable, for example:

```text
20000-40000
```

Never permit a client to bind arbitrary operating-system interfaces or privileged ports.

---

# 8. CLOSED TUNNEL MODE

Closed mode MUST work for arbitrary TCP, not only HTTP.

Therefore a closed tunnel must NOT rely on HTTP headers.

A consumer accesses a closed tunnel through:

```bash
tunnelmate-peer connect \
    tunnel://broker.example.com/<tunnel-id> \
    --token <shared-token> \
    --listen 127.0.0.1:9000
```

Then:

```text
consumer application
       |
localhost:9000
       |
tunnelmate-peer
       |
       | TLS + closed-tunnel token
       v
TunnelMate broker
       |
       | TLS
       v
TunnelMate agent
       |
       v
private service
```

Python equivalent:

```python
peer = tunnelmate.connect(
    peer_address="tunnel://broker.example.com/<tunnel-id>",
    token="shared-secret",
    local_port=9000,
)

peer.start()
```

Wrong tokens must be rejected.

Use constant-time secret comparison where applicable.

Do not reveal unnecessary information about whether a tunnel exists when authentication fails.

---

# 9. ENCRYPTION

Transport security is mandatory.

No plaintext agent↔broker data plane.

No custom cipher.

Use OpenSSL.

Production defaults:

```text
TLS >= 1.2
prefer TLS 1.3
certificate verification enabled
hostname verification enabled
```

Allow development-only self-signed certificates explicitly through configuration.

Never silently disable certificate validation.

Support TLS session resumption where practical.

Do not log:

* shared tokens
* management secrets
* agent secrets
* plaintext user data

---

# 10. ANONYMOUS CREATION WITHOUT GLOBAL API TOKENS

Creating a tunnel must NOT require:

```text
account
login
API key
global API token
OAuth
```

Example:

```http
POST /v1/tunnels
```

Request:

```json
{
  "scope": "open"
}
```

or:

```json
{
  "scope": "closed",
  "shared_token": "optional-user-defined-token"
}
```

If no closed-mode token is provided, generate one securely.

The response may return tunnel-specific capabilities.

Example:

```json
{
  "tunnel_id": "tun_...",
  "scope": "open",
  "peer_address": "tcp://broker.example.com:24117",
  "agent_secret": "...",
  "management_secret": "...",
  "expires_at": "..."
}
```

Important distinction:

**No global token is required to create tunnels.**

However each tunnel MUST have randomly generated tunnel-specific capabilities so strangers cannot modify/delete another person's tunnel.

Return sensitive tunnel credentials once.

Store hashes/HMAC representations server-side wherever practical rather than plaintext secrets.

Use cryptographically secure random generation.

---

# 11. TUNNEL MANAGEMENT SECRET

A tunnel-specific `management_secret` may authorize:

```text
PATCH tunnel
DELETE tunnel
create/update its announcement
rotate closed access token
rotate agent secret
renew lease
```

For example:

```http
X-Tunnel-Management-Secret: ...
```

This is NOT a service-wide API key.

It is a capability scoped to one tunnel.

---

# 12. ABUSE PROTECTION

Public/free/anonymous does not mean unlimited.

Implement configurable protections:

```text
creation rate per source IP
maximum tunnels per source IP
maximum concurrent streams per tunnel
global stream limit
connection establishment rate
idle timeout
handshake timeout
maximum pending streams
public port-range limit
announcement rate limit
announcement size limit
attribute JSON size limit
API body limits
```

Do not create:

* open SOCKS proxy functionality
* arbitrary VPS outbound proxy functionality
* SMTP relay functionality

Add an administrative:

```text
blocked IP/CIDR list
blocked tunnel list
kill tunnel
disable announcement
```

Keep restrictions configurable.

---

# 13. LEASE MODEL

Default tunnel lease:

```text
24 hours
```

The SDK automatically renews the lease while the tunnel remains active.

If an agent remains connected, renewal should normally be transparent.

Expired offline tunnels should eventually release their public port.

Make these settings configurable.

---

# 14. LARGE FILE TRANSFERS

This is a hard requirement.

A tunnel MUST support transfers of at least:

```text
5 GB
```

Prefer effectively unlimited TCP stream length.

The VPS only has approximately:

```text
2 GB SSD
```

Therefore:

**NEVER spool tunnel payload data to disk.**

Do not implement:

```text
receive entire upload
save temporary file
forward temporary file
```

Instead:

```text
source
  ↓
bounded memory buffer
  ↓
socket
```

Use proper backpressure.

Do not let a slow receiver cause unlimited memory growth.

Use small bounded buffers.

Handle partial reads/writes correctly.

Handle:

```text
FIN
RST
half-close
EPIPE
ECONNRESET
ETIMEDOUT
short writes
slow consumer
slow producer
```

Correct TCP half-close handling is important.

A 6+ GB integration test must stream generated data directly between processes and hash it at the sink.

Do NOT create a 6 GB test file on disk.

---

# 15. MEMORY BUDGETING

Design for the stated VPS.

Do not allocate large buffers per stream.

Create configurable limits.

Document estimated memory per active stream.

Target bounded memory consumption even with hundreds of concurrent connections.

Avoid one thread per connection.

Use an event-driven data path.

---

# 16. BROKER: `tunnelmated`

Implement in C.

Responsibilities:

```text
TLS server
agent control connections
data connections
public tunnel listeners
closed peer connections
port allocation
stream pairing
relay
backpressure
heartbeats
timeouts
runtime metrics
runtime tunnel registry
FastAPI IPC
graceful shutdown
```

Use libuv event loops.

Do not put FastAPI/Python in the user-data relay path.

---

# 17. BROKER ↔ FASTAPI IPC

Use a Unix-domain socket, for example:

```text
/run/tunnelmate/broker.sock
```

Restrict its filesystem permissions.

FastAPI uses this channel for:

```text
create runtime tunnel
delete runtime tunnel
change scope
rotate runtime secrets
fetch broker status
fetch connection counts
fetch bytes transferred
fetch health
fetch port utilization
kill stream
reload configuration
```

Existing tunnels should continue forwarding if FastAPI temporarily dies.

---

# 18. PERSISTENCE

Use SQLite for the control-plane database.

Keep it lightweight.

Suggested tables:

```text
tunnels
announcements
admin_users
blocked_ips
audit_events
```

Do NOT store traffic payloads.

Tunnel statistics may remain mostly in memory, periodically snapshotting only necessary aggregates.

Avoid excessive write amplification.

---

# 19. ANNOUNCEMENT / SERVICE REGISTRY

Create a public service registry.

Endpoint examples:

```text
POST   /v1/announce
GET    /v1/announce
GET    /v1/announce/{id}
PATCH  /v1/announce/{id}
DELETE /v1/announce/{id}
```

Also support:

```text
GET /v1/announce/search
```

Search/filter by:

```text
service name
service ID
scope
peer address
attributes
online status
```

---

# 20. ANNOUNCEMENT DATA MODEL

Core model:

```json
{
  "announcement_id": "ann_...",
  "tunnel_id": "tun_...",
  "peer_address": "tcp://broker.example.com:24117",
  "scope": "open",
  "service_name": "Yolo Inference Service",
  "service_id": "yolov11-detection",
  "llms": "https://peer.example/llms.txt",
  "attributes": {
    "version": 11,
    "size": "n"
  }
}
```

For YOLO this may contain:

```json
{
  "version": 11,
  "size": "n"
}
```

Valid example sizes might include:

```text
n
s
m
l
x
```

But DO NOT hard-code YOLO attributes into TunnelMate.

Attributes are service-defined.

---

# 21. GENERIC SERVICE ATTRIBUTES

For FFmpeg, for example:

```json
{
  "service_name": "FFmpeg Transcoding",
  "service_id": "ffmpeg",
  "llms": "https://example.com/llms.txt",
  "attributes": {
    "version": "8.x",
    "codecs": [
      "h264",
      "h265",
      "av1"
    ],
    "hwaccel": false
  }
}
```

`attributes` must support generic JSON values.

Limit:

```text
maximum nesting
maximum keys
maximum total serialized size
```

to prevent abuse.

---

# 22. ANNOUNCEMENT OWNERSHIP

Normal announcements should be attached to a TunnelMate tunnel.

Do not allow one anonymous user to alter another tunnel's listing.

Use its tunnel management capability.

`peer_address` should normally be derived from the tunnel rather than blindly trusted from arbitrary user input.

Admin users may create manual entries where needed.

---

# 23. `llms.txt`

Every announcement MUST contain an `llms` URL.

At minimum validate:

```text
valid URL structure
http:// or https://
reasonable maximum length
```

Do NOT naively fetch arbitrary URLs from the VPS because this creates SSRF risk.

If implementing server-side verification, create a hardened verifier with:

```text
DNS resolution checks
block localhost
block loopback
block link-local
block RFC1918/private addresses
block metadata-service addresses
redirect limits
response-size limit
timeout
content-type handling
DNS rebinding precautions
```

Make active verification optional.

---

# 24. TUNNELMATE'S OWN `llms.txt`

FastAPI MUST serve:

```text
GET /llms.txt
```

Content type:

```text
text/plain; charset=utf-8
```

It should explain concisely:

```text
what TunnelMate is
how tunnels work
open vs closed
API endpoint locations
OpenAPI location
announcement search
Python SDK
peer addressing
authentication model
important limitations
documentation links
```

Also expose:

```text
/openapi.json
/docs
/redoc
```

when enabled.

---

# 25. FASTAPI CONTROL PLANE

Use modern FastAPI and Pydantic.

Keep dependencies reasonable.

Suggested API groups:

```text
/v1/tunnels
/v1/announce
/v1/admin
/v1/status
/v1/health
```

Health endpoints:

```text
GET /health/live
GET /health/ready
```

Readiness should check important dependencies such as broker IPC.

Liveness should remain simpler.

---

# 26. ADMIN CONTROL PANEL

Create a developer-oriented admin interface.

Do not create a marketing dashboard.

Design characteristics:

```text
dense
functional
monospace-friendly
minimal
neutral
fast
keyboard-friendly
no unnecessary animations
no gradients
no glassmorphism
no giant cards
no decorative illustrations
```

Prefer:

```text
server-rendered HTML
small vanilla JavaScript
minimal CSS
```

Use a small visualization library only where valuable.

Avoid a large SPA unless there is a strong technical justification.

---

# 27. ADMIN FEATURES

Admin must be able to:

```text
view all tunnels
view online/offline state
view public/closed scope
view peer address
view tunnel ID
view uptime
view active connections
view bytes RX/TX
view creation time
view expiration
delete tunnel
disable tunnel
search tunnels
filter tunnels
inspect streams
kill streams
```

Announcement administration:

```text
view
search
add
edit
remove
disable
verify
```

Search should support:

```text
YOLO
ffmpeg
service_id
scope
attribute values
tunnel ID
peer address
```

---

# 28. ADMIN AUTHENTICATION

The public tunnel API is anonymous.

The **admin API is not anonymous**.

Implement secure admin authentication.

A simple single-administrator deployment is acceptable initially.

Requirements:

```text
password stored as strong hash
secure session cookie
HttpOnly
SameSite
Secure in production
CSRF protection for state-changing browser requests
logout
login rate limiting
```

Do not ship a default hard-coded admin password.

Initialize credentials from environment/bootstrap command.

---

# 29. ADMIN NETWORK DIAGRAM

Provide a live topology view.

Example:

```text
                  BROKER
               /     |      \
              /      |       \
          tun_1    tun_2    tun_3
            |         |        |
          YOLO      FFmpeg    SSH
            |
        3 streams
```

Show:

```text
broker
connected agents
tunnels
announced services
active peer connections
scope
health
```

Use a lightweight graph visualization.

Do not make it ornamental.

Clicking a node should show technical properties.

---

# 30. ADDITIONAL ADMIN VISUALIZATIONS

Useful operational panels should include:

```text
CPU usage
RAM usage
open file descriptors
broker uptime
active tunnels
active streams
public ports used/free
bytes/sec RX
bytes/sec TX
connection creation rate
failed authentication count
agent reconnects
API errors
```

Use bounded in-memory time-series samples.

Do not install a huge monitoring stack just for the default deployment.

Expose Prometheus-compatible metrics optionally if straightforward.

---

# 31. PYTHON SDK

Create a proper Python package:

```text
tunnelmate
```

Target a clean API.

The following style MUST work:

```python
import tunnelmate

conf = {}

conf["host"] = "localhost"
conf["port"] = 5675

conf["service_name"] = "Yolo Inference Service"
conf["service_id"] = "yolov11-detection"

conf["scope"] = "open"

conf["llms"] = "http://localhost:5675/llms.txt"

conf["attributes"] = {
    "version": 11,
    "size": "n",
}

tunnel = tunnelmate.new(
    broker_url,
    conf,
)

tunnel.announce()
tunnel.start()
```

Expose a more typed configuration model as well.

For example:

```python
from tunnelmate import TunnelConfig, new

conf = TunnelConfig(
    host="127.0.0.1",
    port=5675,
    service_name="Yolo Inference Service",
    service_id="yolov11-detection",
    scope="open",
    llms="http://127.0.0.1:5675/llms.txt",
    attributes={
        "version": 11,
        "size": "n",
    },
)

tunnel = new(
    "https://broker.example.com",
    conf,
)

tunnel.announce()
tunnel.start()
```

---

# 32. PYTHON SDK LIFECYCLE

Support:

```python
tunnel.start()
tunnel.stop()
tunnel.delete()

tunnel.announce()
tunnel.unannounce()

tunnel.status()
tunnel.stats()

tunnel.rotate_token()
tunnel.renew()

tunnel.wait()
```

Also support context manager semantics where sensible.

Example:

```python
with tunnelmate.new(broker_url, conf) as tunnel:
    tunnel.announce()
    tunnel.start()
    tunnel.wait()
```

Prevent accidental resource leaks.

---

# 33. SDK AND C AGENT

The Python SDK should NOT rewrite the performance-sensitive tunnel protocol in Python.

The SDK should manage the compiled C agent.

Options include:

```text
launch subprocess
communicate over local Unix socket
communicate over stdin/control pipe
```

Choose the simplest robust implementation.

Avoid placing secrets in process command-line arguments because other local processes may inspect command lines.

Prefer:

```text
stdin
protected file descriptor
0600 temporary config
local Unix socket
```

Clean secrets up afterward.

---

# 34. OPTIONAL MESSAGE HANDLER

Support the requested API:

```python
tunnel.set_message_handler(handler)
```

However TCP is a byte stream.

There are no inherent application-level messages.

Therefore define the handler in terms of chunks.

Example:

```python
def handler(direction, data, context):
    # direction:
    # "peer_to_service"
    # "service_to_peer"

    return data
```

Allow:

```text
bytes -> modified bytes
None -> drop chunk
```

Clearly document that changing length/content may alter application protocol semantics.

---

# 35. FAST PATH VS HANDLER PATH

Default path:

```text
peer
↕
C broker
↕
C agent
↕
service
```

No Python payload interception.

If `set_message_handler()` is enabled:

```text
C agent
↕
local SDK interception proxy
↕
service
```

The slower Python path is acceptable because the user explicitly requested interception.

Document that for large-file/high-throughput use cases the handler should normally remain disabled.

---

# 36. CLOSED-MODE SDK

Example producer:

```python
conf = TunnelConfig(
    host="127.0.0.1",
    port=5675,
    service_name="Private YOLO",
    service_id="private-yolo",
    scope="closed",
    shared_token="...",
)

tunnel = tunnelmate.new(
    broker_url,
    conf,
)

tunnel.start()
```

Consumer:

```python
peer = tunnelmate.connect(
    tunnel.peer_address,
    token="...",
    local_port=9000,
)

peer.start()
```

Then the consuming application uses:

```text
127.0.0.1:9000
```

---

# 37. CLI

Provide:

```bash
tunnelmate-agent --config config.toml
```

and:

```bash
tunnelmate-peer connect ...
```

Python package may also expose:

```bash
tunnelmate new
tunnelmate start
tunnelmate connect
tunnelmate announce
tunnelmate status
```

Do not duplicate the performance-sensitive tunnel implementation in Python.

---

# 38. CONFIGURATION

Support environment variables and config files.

C components may use TOML/JSON or another small parser.

Document every field.

Example broker configuration:

```text
listen_host
control_port
public_port_start
public_port_end
tls_cert
tls_key
max_tunnels
max_streams
max_streams_per_tunnel
handshake_timeout
idle_timeout
heartbeat_interval
broker_socket
log_level
```

---

# 39. LOGGING

Use structured logs.

Example fields:

```text
timestamp
level
component
event
tunnel_id
stream_id
remote_ip
duration_ms
error_code
```

Never log secrets.

Never log tunnel payloads.

Support:

```text
debug
info
warning
error
```

Log rotation should be handled by journald/systemd in normal deployment.

---

# 40. GRACEFUL SHUTDOWN

On SIGTERM:

```text
stop accepting new tunnels
stop accepting new streams
tell agents GOING_AWAY where possible
allow active streams a configurable grace period
close remaining connections
flush minimal state
exit
```

Do not abruptly corrupt streams unless the shutdown grace period expires.

---

# 41. AGENT RECONNECT

If an agent loses its broker connection:

```text
detect failure
close orphaned active streams
reconnect with exponential backoff + jitter
re-register tunnel
resume accepting NEW connections
```

Do not pretend an interrupted raw TCP connection can be transparently resumed.

Existing connections may fail.

New connections should recover automatically after agent reconnection.

---

# 42. BACKPRESSURE

This must be implemented correctly.

For each relay direction:

```text
read only while downstream buffer has capacity
pause source reads when destination cannot keep up
resume after destination drains
```

Never append indefinitely to a dynamic buffer.

Create explicit high/low watermarks.

---

# 43. SECURITY REQUIREMENTS

Perform a threat model.

Address at least:

```text
malformed packets
oversized frames
credential brute force
credential leakage
token replay
timing comparison
port exhaustion
connection exhaustion
file descriptor exhaustion
memory exhaustion
slowloris behavior
announcement spam
XSS in announcement metadata
SQL injection
SSRF through llms URLs
CSRF in admin panel
admin brute force
path traversal
log injection
integer overflow
use-after-free
double-free
SIGPIPE
TLS downgrade
certificate validation failure
```

Use parameterized SQL.

Escape rendered HTML.

Set security headers.

---

# 44. LINUX HARDENING

Provide systemd service units.

Run services as dedicated unprivileged users.

The public tunnel range should use unprivileged ports by default.

Add useful systemd hardening where compatible, such as:

```text
NoNewPrivileges
PrivateTmp
ProtectSystem
ProtectHome
RestrictSUIDSGID
LimitNOFILE
```

Do not apply a hardening setting blindly if it breaks required networking/filesystem access.

Document decisions.

---

# 45. FAILURE CASES DOCUMENT

Create:

```text
docs/failure-cases.md
```

For every failure include:

```text
failure
expected behavior
user-visible behavior
log behavior
automatic recovery behavior
test covering it
```

At minimum cover:

```text
broker unavailable
broker restart
FastAPI unavailable
SQLite unavailable
agent local service unavailable
local service closes early
agent network disconnect
public peer disconnect
closed peer wrong token
expired tunnel
port exhaustion
public port collision
TLS certificate invalid
TLS certificate expired
DNS failure
malformed protocol message
oversized message
heartbeat timeout
slow peer
slow local service
5+ GB stream
client half-close
server half-close
RST
connection flood
announcement duplicate
invalid llms URL
broker IPC unavailable
disk nearly full
low memory
file descriptor limit reached
SIGTERM
SIGKILL
```

---

# 46. TESTING STRATEGY

Implement:

```text
C unit tests
Python unit tests
API tests
protocol parser tests
integration tests
end-to-end tests
failure tests
security tests
load tests
```

Use:

```text
pytest
ASAN
UBSAN
clang-tidy where useful
Valgrind where practical
```

Fuzz protocol parsers if tooling permits.

---

# 47. NAT TEST

Create a Linux-network-namespace or Docker-based integration test that simulates:

```text
public Internet peer
VPS broker
NAT
private TunnelMate agent
private local service
```

The service behind NAT must initiate the connection outward.

The test must demonstrate that the Internet side cannot connect directly to the NAT host but can reach it through TunnelMate.

---

# 48. LARGE TRANSFER TEST

Create an automated test transferring at least:

```text
6 GB
```

through the tunnel.

Generate the bytes as a deterministic stream.

Do not store them.

Example architecture:

```text
deterministic generator
        |
        | 6 GB
        v
TunnelMate tunnel
        |
        v
streaming SHA-256 sink
```

Compare sender and receiver hashes.

Record:

```text
bytes transferred
duration
throughput
broker peak RSS
agent peak RSS
errors
```

Make the 6 GB test optional in ordinary unit CI but mandatory as a documented extended test.

Also provide smaller CI versions.

---

# 49. CONCURRENCY TESTS

Test scenarios such as:

```text
100 idle tunnels
100 simultaneous connections
256 simultaneous connections
slow clients
rapid connect/disconnect
wrong closed tokens
agent reconnect storm
```

Make limits configurable so constrained CI machines can run smaller versions.

---

# 50. PERFORMANCE TESTING

Create a benchmark command.

Measure:

```text
throughput
CPU
memory
connections/sec
latency overhead
```

Compare:

```text
direct localhost TCP
TunnelMate open tunnel
TunnelMate closed tunnel
TunnelMate with Python handler
```

Do not make unsupported performance claims.

Report measured results.

---

# 51. API TESTS

Verify:

```text
anonymous tunnel creation succeeds
creation requires no global API token
modify without management secret fails
modify with management secret succeeds
delete authorization works
open tunnel address is valid
closed tunnel has no unauthenticated public access
announcement requires llms field
arbitrary attributes survive round-trip
search works
admin APIs require admin authentication
```

---

# 52. ADMIN UI TESTS

At minimum validate important server-side behavior and routes.

If using browser automation, keep it lightweight.

Test:

```text
login
tunnel table
search
delete
announcement edit
topology endpoint
stats endpoint
CSRF rejection
```

---

# 53. DOCUMENTATION

Produce detailed documentation.

Required:

```text
README.md

docs/
├── quickstart.md
├── architecture.md
├── protocol.md
├── api.md
├── python-sdk.md
├── announcements.md
├── security.md
├── threat-model.md
├── deployment.md
├── configuration.md
├── operations.md
├── monitoring.md
├── performance.md
├── failure-cases.md
├── testing.md
├── troubleshooting.md
└── development.md
```

Use Mermaid diagrams where useful.

---

# 54. QUICKSTART

The quickstart should reach this experience rapidly.

Server:

```bash
sudo tunnelmate-install
```

or documented equivalent.

Service user:

```python
import tunnelmate

conf = {
    "host": "127.0.0.1",
    "port": 5675,
    "scope": "open",
    "service_name": "Yolo Inference Service",
    "service_id": "yolov11-detection",
    "llms": "http://127.0.0.1:5675/llms.txt",
    "attributes": {
        "version": 11,
        "size": "n",
    },
}

tunnel = tunnelmate.new(
    "https://broker.example.com",
    conf,
)

tunnel.announce()
tunnel.start()

print(tunnel.peer_address)
```

Result:

```text
tcp://broker.example.com:24317
```

---

# 55. OPENAPI

FastAPI should generate a useful OpenAPI definition.

Add:

```text
clear operation IDs
descriptions
request examples
response examples
error schemas
```

Do not leave the generated API largely undocumented.

---

# 56. ERROR FORMAT

Use a consistent API error format.

For example:

```json
{
  "error": {
    "code": "TUNNEL_NOT_FOUND",
    "message": "Tunnel was not found.",
    "request_id": "req_..."
  }
}
```

Never expose stack traces in production API responses.

---

# 57. IDENTIFIERS

Generate non-sequential public IDs.

Examples:

```text
tun_<random>
ann_<random>
str_<random>
req_<random>
```

Do not expose simple incrementing database IDs as external identifiers.

---

# 58. REQUEST IDs

FastAPI requests should receive a request ID.

Propagate useful correlation IDs into broker control operations.

This will make debugging substantially easier.

---

# 59. DATABASE INDEXING

Add indexes for common registry queries:

```text
tunnel_id
service_id
service_name
scope
status
created_at
expires_at
```

Use SQLite JSON capabilities for attributes only where reliable.

Do not create an unnecessarily complicated search system.

---

# 60. ADMIN AUDIT LOG

Record administrative operations such as:

```text
login
logout
delete tunnel
disable tunnel
edit announcement
block IP
unblock IP
kill stream
```

Store metadata, not payloads or secrets.

---

# 61. RESOURCE LIMITS

Document and expose configuration for:

```text
max active tunnels
max active streams
max streams per tunnel
max announcements
max API request size
max announcement size
max protocol frame size
max pending streams
max connect rate
```

Choose conservative defaults for a 2 GB VPS.

---

# 62. DISK USAGE

Because disk is only around 2 GB:

Do not:

```text
store traffic
store temporary uploads
write per-packet logs
retain unlimited logs
retain unlimited metrics
```

Use:

```text
journald limits
SQLite
bounded metric history
small static web assets
```

Provide a documented approximate disk budget.

---

# 63. API/BROKER PORTS

Make all ports configurable.

A reasonable development layout is:

```text
FastAPI:
127.0.0.1:8000

HTTPS reverse proxy:
0.0.0.0:443

TunnelMate agent control/data:
0.0.0.0:7000

Open tunnel range:
20000-40000
```

Do not hard-code these assumptions into the protocol.

Document how a future deployment can place TunnelMate transport on TCP/443 if restrictive outbound firewalls require it.

---

# 64. IPv6

Do not make IPv6 mandatory for v1, but avoid assumptions that make future IPv6 support difficult.

Use address-family-neutral APIs where practical.

---

# 65. OBSERVABILITY IPC

The broker should expose lightweight runtime stats to FastAPI over the Unix socket.

Example:

```json
{
  "uptime": 91820,
  "tunnels_online": 31,
  "streams_active": 72,
  "rx_bytes": 1827318273,
  "tx_bytes": 918271827,
  "ports_used": 22
}
```

FastAPI can stream updates to the admin interface using SSE or WebSocket.

Prefer SSE if one-directional updates are sufficient.

---

# 66. CODE QUALITY

C:

```text
-Wall
-Wextra
-Wpedantic
```

Use stronger warnings during development where practical.

Treat unsafe compiler warnings seriously.

Use clearly owned objects and lifecycle rules.

Document ownership for:

```text
tunnel
stream
connection
buffer
TLS object
libuv handle
```

Avoid hidden global mutable state.

---

# 67. PYTHON QUALITY

Use:

```text
type annotations
pytest
ruff
mypy or pyright where practical
Pydantic models
structured logging
```

Keep the SDK synchronous-friendly but provide asynchronous functionality where it provides actual value.

A user should not be forced to understand asyncio just to expose a port.

---

# 68. BUILD

Provide commands such as:

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build
```

Python:

```bash
pip install -e ./python-sdk
pip install -e ./control
```

Provide development dependency instructions for Ubuntu/Debian.

---

# 69. PACKAGING

Produce installable C binaries.

Create:

```text
install target
systemd units
example configs
Python wheel configuration
```

Do not require Docker to run production.

Docker may be provided for development/integration testing.

---

# 70. DEPLOYMENT SCRIPT

Provide an idempotent deployment/bootstrap approach for Ubuntu.

It should:

```text
create system user
create directories
install binaries
install Python virtual environment
initialize DB
configure environment
install systemd services
set permissions
start services
verify health
```

Do not hide failures.

---

# 71. SECRET FILE PERMISSIONS

Use appropriate filesystem permissions.

Example:

```text
/etc/tunnelmate/
    root:tunnelmate
    0750

secret files:
    0640 or stricter
```

Do not expose secrets in static web content.

---

# 72. ADMIN UI ROUTES

Potential routes:

```text
/admin
/admin/login
/admin/tunnels
/admin/tunnels/{id}
/admin/announcements
/admin/topology
/admin/system
/admin/logs
```

Keep interface simple.

---

# 73. SERVICE SEARCH

Support queries such as:

```text
/v1/announce?service=yolo
```

and filters resembling:

```text
service_id=yolov11-detection
scope=open
attribute.size=n
attribute.version=11
```

Do not implement a complex query language unless necessary.

---

# 74. ANNOUNCEMENT STATUS

Expose derived fields such as:

```text
online
last_seen
created_at
updated_at
expires_at
```

An announcement attached to an offline tunnel should clearly show that state.

Do not silently delete useful metadata immediately when an agent temporarily disconnects.

---

# 75. ADMIN DELETE SEMANTICS

Deleting a tunnel must:

```text
stop new connections
close listener
notify connected agent
terminate active streams according to configured policy
remove/disable announcements
release allocated port
persist deletion
audit operation
```

Make the behavior explicit.

---

# 76. API DELETE SEMANTICS

Owner deletion requires the tunnel's management capability.

Return deterministic status.

Deletion should be idempotent where reasonable.

---

# 77. HEARTBEAT

Implement heartbeat with configurable:

```text
interval
timeout
missed count
```

Avoid synchronized reconnect storms by adding jitter.

---

# 78. PROTOCOL MALFORMED-INPUT HANDLING

A malformed client must never crash the broker.

For malformed packets:

```text
reject
log bounded diagnostic information
close connection
increment metric
```

Do not dump arbitrary attacker-controlled binary data into logs.

---

# 79. TEST WITH SANITIZERS

Add a sanitizer build.

Example:

```text
-DTUNNELMATE_SANITIZE=ON
```

Run important integration tests with:

```text
AddressSanitizer
UndefinedBehaviorSanitizer
```

where compatible.

---

# 80. NO PAYLOAD INSPECTION

The broker does not need to understand:

```text
HTTP
YOLO
FFmpeg
SSH
database protocol
gRPC
custom binary protocols
```

Treat data as bytes.

Announcement metadata describes services but does not alter transport behavior.

---

# 81. OPTIONAL FUTURE EXTENSIONS

Design clean extension points, but DO NOT delay v1 for them.

Possible later additions:

```text
UDP
HTTP hostname routing
QUIC
pre-connected worker pools
connection multiplexing
end-to-end encrypted closed tunnels
mTLS
accounts
reserved public ports
custom domains
bandwidth quotas
distributed brokers
multi-VPS federation
WebSocket tunnels
service health checks
```

Document these as future work.

Do not implement all of them now.

---

# 82. ACCEPTANCE CRITERIA

The project is not complete until all of the following work.

## Open service

A computer behind NAT runs:

```python
tunnel = tunnelmate.new(...)
tunnel.announce()
tunnel.start()
```

Another Internet computer can connect to:

```text
broker:allocated_port
```

and use the service.

No global API token was required.

## Closed service

An unauthorized raw Internet connection cannot access it.

A peer possessing the shared token can run:

```text
tunnelmate-peer
```

or:

```python
tunnelmate.connect(...)
```

and access the service locally.

## Registry

User can announce arbitrary service metadata.

Required fields include:

```text
peer address
scope
service name
service ID
llms URL
attributes
```

## Admin

Administrator can:

```text
view
search
delete
disable
inspect
visualize
manage announcements
```

## Large stream

A streaming transfer larger than 5 GB succeeds with matching hash without payload disk spooling.

## Recovery

Agent reconnects after transient broker/network loss and begins accepting new connections again.

## Isolation

FastAPI restart does not terminate already-active relay streams.

## Documentation

Complete installation, architecture, protocol, API, SDK, testing, failure-mode and deployment documentation exists.

---

# 83. IMPLEMENTATION ORDER

Implement in this order.

### Phase 1 — architecture/spec

Create:

```text
architecture.md
protocol.md
threat-model.md
data models
API contract
```

Resolve contradictions before implementation.

### Phase 2 — C broker

Implement:

```text
event loop
TLS
control sessions
tunnel registry
public listener allocation
stream association
relay
backpressure
timeouts
metrics
```

### Phase 3 — C agent

Implement:

```text
broker connection
registration
heartbeat
local TCP connection
data channel
reconnect
```

### Phase 4 — end-to-end open tunnel

Demonstrate real TCP traffic.

Do not proceed solely from mocked tests.

### Phase 5 — closed peer

Implement:

```text
tunnelmate-peer
shared-token authentication
local listening proxy
```

### Phase 6 — FastAPI

Implement persistence and control API.

### Phase 7 — announce service

Implement generic registry.

### Phase 8 — Python SDK

Wrap control API and C binaries.

### Phase 9 — admin UI

Implement management and topology views.

### Phase 10 — hardening/tests/docs

Complete all failure, security, large-transfer and resource testing.

---

# 84. DEVELOPMENT BEHAVIOR

While implementing:

1. Inspect the existing repository before changing files.
2. Preserve useful existing code.
3. Do not create placeholder implementations and call the task complete.
4. Run tests after each meaningful subsystem.
5. When a test fails, determine the underlying cause rather than weakening the assertion.
6. Keep the data path small and understandable.
7. Minimize runtime dependencies.
8. Prefer boring, auditable networking code over clever abstractions.
9. Explain any major deviation from this specification.
10. Record important architecture decisions in ADR-style documentation.
11. Never silently downgrade security to make a test pass.
12. Do not replace bounded streaming with whole-file buffering.
13. Do not put Python in the normal payload hot path.
14. Do not implement cryptography yourself.
15. Do not require an account/global API token for ordinary tunnel creation.

---

# 85. FINAL DELIVERABLE

When implementation is complete, return a technical completion report containing:

```text
architecture summary
repository tree
implemented features
protocol summary
security model
API endpoints
Python SDK usage
admin UI capabilities
build instructions
deployment instructions
test results
large-transfer result
benchmark results
known limitations
failure cases tested
remaining future work
```

Include exact commands needed to run the finished system locally and on the intended small VPS.

The final system should feel like:

```text
FRP/ngrok-style reverse tunneling
+
anonymous free tunnel creation
+
closed shared-token tunnels
+
service discovery/announcement registry
+
llms.txt discovery
+
minimal developer admin console
+
Python SDK
```

while keeping the **performance-sensitive tunnel data plane implemented in C** and the **management/control layer implemented with FastAPI/Python**.


# UDP SUPPORT — MANDATORY UPDATE

Modify the TunnelMate specification so **both TCP and UDP are production-supported in v1**.

Any previous statement saying:

```text
TCP only for v1
```

is removed.

TunnelMate v1 MUST support:

```text
TCP
UDP
```

Both protocols must work through NAT/CGNAT using outbound connections initiated by `tunnelmate-agent`.

---

# 1. TRANSPORT MODEL

A tunnel has an explicit transport:

```json
{
  "protocol": "tcp"
}
```

or:

```json
{
  "protocol": "udp"
}
```

The API and SDK should also accept aliases where sensible:

```python
protocol="tcp"
protocol="udp"
```

Do not infer UDP/TCP solely from service names.

---

# 2. UDP MUST PRESERVE DATAGRAM SEMANTICS

UDP is not a byte stream.

Every received UDP packet must remain a distinct datagram.

For example:

```text
UDP packet A: 120 bytes
UDP packet B: 800 bytes
UDP packet C: 57 bytes
```

must arrive at the destination as:

```text
120-byte datagram
800-byte datagram
57-byte datagram
```

Do NOT merge them into:

```text
977-byte stream
```

and do NOT split them arbitrarily unless IP-level fragmentation naturally occurs below the application.

---

# 3. DO NOT IMPLEMENT PRODUCTION UDP-OVER-TCP

Do NOT make the production architecture:

```text
UDP
 ↓
TCP/TLS tunnel
 ↓
UDP
```

as the primary UDP implementation.

TCP head-of-line blocking changes UDP behavior significantly during packet loss and congestion.

For production UDP forwarding, use a real encrypted datagram-capable transport.

Preferred architecture:

```text
Internet UDP Peer
       │
       ▼
TunnelMate Broker UDP Socket
       │
       ▼
Encrypted QUIC Datagram Transport
       │
       ▼
TunnelMate Agent
       │
       ▼
Local UDP Service
```

Preferred technology:

```text
QUIC + QUIC DATAGRAM
```

using a mature C implementation.

Candidates may include:

```text
ngtcp2
quiche
lsquic
another actively maintained, audited C-compatible QUIC library
```

The coding agent must evaluate the current repository/platform compatibility and choose the smallest robust dependency.

Do NOT implement QUIC cryptography yourself.

Use an established QUIC/TLS library.

If QUIC DATAGRAM support proves impractical for the target platform, a properly designed DTLS-based datagram transport is an acceptable alternative.

The implementation decision must be documented in an ADR.

---

# 4. CONTROL PLANE MAY REMAIN TCP/TLS

It is acceptable and desirable for agent control signaling to remain:

```text
TCP + TLS
```

For example:

```text
agent
   │
   │ TLS control connection
   ▼
broker
```

The UDP forwarding path may separately use:

```text
QUIC/UDP
```

This means TunnelMate can have:

```text
TCP/TLS control plane
TCP/TLS TCP-data plane
QUIC UDP-data plane
```

The protocols should remain logically separated.

---

# 5. UDP OPEN TUNNEL

An open UDP tunnel should allocate a public UDP port.

Example:

```text
udp://broker.example.com:25421
```

Flow:

```text
Internet UDP Client
        │
        │ UDP
        ▼
broker.example.com:25421
        │
        │ encrypted datagram tunnel
        ▼
TunnelMate Agent
        │
        │ UDP
        ▼
127.0.0.1:5000
```

Example configuration:

```python
import tunnelmate

conf = {
    "host": "127.0.0.1",
    "port": 5000,
    "protocol": "udp",
    "scope": "open",
    "service_name": "UDP Telemetry Service",
    "service_id": "telemetry-v1",
    "llms": "http://127.0.0.1:8080/llms.txt",
    "attributes": {
        "format": "binary"
    },
}

tunnel = tunnelmate.new(
    broker_url,
    conf,
)

tunnel.announce()
tunnel.start()
```

Returned address:

```text
udp://broker.example.com:25421
```

---

# 6. UDP CLOSED TUNNEL

Closed UDP tunnels must require TunnelMate-aware peer software.

Do NOT attempt to authenticate arbitrary raw UDP packets with an HTTP-style token.

Consumer:

```bash
tunnelmate-peer connect \
    tunnel://broker.example.com/<tunnel-id> \
    --protocol udp \
    --token <shared-token> \
    --listen 127.0.0.1:9000
```

Then the local application sends ordinary UDP packets to:

```text
127.0.0.1:9000
```

Architecture:

```text
Consumer UDP App
      │
      │ UDP
      ▼
127.0.0.1:9000
      │
      ▼
tunnelmate-peer
      │
      │ authenticated encrypted transport
      ▼
TunnelMate Broker
      │
      │ encrypted UDP transport
      ▼
TunnelMate Agent
      │
      │ UDP
      ▼
Private UDP Service
```

---

# 7. UDP FLOW IDENTIFICATION

UDP has no connection handshake.

The broker must therefore maintain temporary flow/session mappings.

A UDP flow may be identified by a tuple resembling:

```text
tunnel_id
source_ip
source_port
destination_public_port
```

Internally assign:

```text
udp_flow_id
```

Example:

```text
uflow_<random>
```

The broker should map:

```text
203.0.113.20:41020
```

to the appropriate virtual flow for a configurable amount of time.

Do not create permanent state for every historical UDP sender.

---

# 8. UDP FLOW TIMEOUT

Implement configurable inactivity expiration.

Example:

```text
udp_flow_idle_timeout = 60 seconds
```

Different services may require longer values.

Support broker configuration such as:

```text
udp_flow_idle_timeout
udp_max_flows
udp_max_flows_per_tunnel
udp_max_datagram_size
udp_flow_creation_rate
```

Expired mappings must be removed automatically.

---

# 9. BIDIRECTIONAL UDP

Replies from the local service must return to the correct Internet sender.

Example:

```text
Internet client A
  203.0.113.10:50001
          │
          ▼
       Broker
          │
          ▼
       Agent
          │
          ▼
     UDP Service
          │
          ▼
       reply
          │
          ▼
Internet client A
```

If client B is simultaneously using the tunnel:

```text
203.0.113.11:50002
```

the replies must not be mixed.

Preserve independent flow mappings.

---

# 10. MULTIPLE UDP CLIENTS

A single announced UDP service must support many remote senders concurrently.

Example:

```text
Client A ──┐
Client B ──┤
Client C ──┼──> UDP tunnel ──> local UDP service
Client D ──┘
```

The agent must preserve sufficient metadata to route responses to the proper remote endpoint.

---

# 11. UDP DATAGRAM FRAME

If TunnelMate needs its own metadata around datagrams, define an explicit datagram envelope.

Conceptually:

```text
+-----------------------------+
| protocol version            |
| message type                |
| tunnel ID / compact handle  |
| UDP flow ID                 |
| payload length              |
| metadata flags              |
+-----------------------------+
| original UDP payload        |
+-----------------------------+
```

Requirements:

```text
strict length validation
defined byte order
fixed maximum header size
bounded metadata
no uncontrolled allocations
```

Do not expose attacker-controlled lengths directly to allocations.

---

# 12. UDP DATAGRAM SIZE

Support normal UDP datagrams safely.

The protocol must support datagrams up to the maximum legal UDP payload where transport permits, but TunnelMate should use a conservative operational size by default.

Make configurable:

```text
udp_max_datagram_size
```

Do not silently truncate a datagram.

If a packet exceeds the supported tunnel size:

```text
drop it
increment metric
log bounded diagnostic information
```

where appropriate.

Never deliver a silently truncated packet to the destination application.

---

# 13. MTU AND FRAGMENTATION

Explicitly test MTU-related behavior.

Avoid creating excessive IP fragmentation.

If the encrypted tunnel has lower effective MTU than the incoming UDP packet, use the chosen transport's supported fragmentation/segmentation strategy or explicitly reject oversized datagrams.

Do not invent an unsafe fragmentation mechanism.

Document:

```text
effective tunnel MTU
maximum recommended UDP payload
behavior for oversized datagrams
IPv4 considerations
IPv6 considerations
```

---

# 14. QUIC DATAGRAM BEHAVIOR

If QUIC DATAGRAM is selected:

Use unreliable QUIC DATAGRAM frames for user UDP payloads.

Do NOT convert every UDP datagram into a reliable QUIC stream.

Control messages may use reliable QUIC streams if desired.

Conceptually:

```text
QUIC connection
├── reliable control stream
└── unreliable DATAGRAM frames
```

This preserves UDP-like behavior much better than TCP encapsulation.

---

# 15. UDP ENCRYPTION

UDP user traffic must be encrypted between TunnelMate components.

For example:

```text
Internet peer
    │ raw UDP
    ▼
Broker
    │
    │ QUIC encryption
    ▼
Agent
    │ raw UDP
    ▼
Local service
```

For closed-mode peer connections:

```text
tunnelmate-peer
    │
    │ encrypted authenticated QUIC
    ▼
broker
```

Never invent a packet encryption scheme.

---

# 16. TCP AND UDP MAY SHARE THE SAME SERVICE ID

Do not assume a service ID uniquely identifies a protocol.

For example, a service could expose:

```text
DNS TCP
DNS UDP
```

These may be separate TunnelMate tunnels.

Announcement metadata must therefore contain:

```json
{
  "protocol": "udp"
}
```

---

# 17. UPDATED ANNOUNCEMENT MODEL

Example:

```json
{
  "announcement_id": "ann_...",
  "tunnel_id": "tun_...",
  "peer_address": "udp://broker.example.com:25421",
  "protocol": "udp",
  "scope": "open",
  "service_name": "Game Server",
  "service_id": "my-game-server",
  "llms": "https://example.com/llms.txt",
  "attributes": {
    "version": "1.4",
    "region": "asia"
  }
}
```

Search must support:

```text
protocol=tcp
protocol=udp
```

---

# 18. PUBLIC PORT ALLOCATION

TCP and UDP port namespaces are independent.

Therefore it is legal for:

```text
TCP 25000
UDP 25000
```

to both exist.

Broker tracking must distinguish:

```text
(protocol, port)
```

rather than port alone.

---

# 19. OPTIONAL SAME-PORT ALLOCATION

If practical, TunnelMate may attempt to give related TCP/UDP tunnels the same numerical port.

Example:

```text
tcp://broker.example.com:27015
udp://broker.example.com:27015
```

This is useful for game servers and services using both transports.

Do not make this mandatory.

---

# 20. PYTHON SDK

Support:

```python
from tunnelmate import TunnelConfig

conf = TunnelConfig(
    host="127.0.0.1",
    port=5000,
    protocol="udp",
    scope="open",
    service_name="UDP Service",
    service_id="udp-demo",
    llms="http://127.0.0.1:8080/llms.txt",
)
```

Validate:

```text
protocol ∈ {"tcp", "udp"}
```

---

# 21. MESSAGE HANDLER FOR UDP

For TCP:

```python
handler(direction, data, context)
```

operates on arbitrary byte chunks.

For UDP:

```python
handler(direction, datagram, context)
```

must receive exactly one datagram at a time.

Example:

```python
def handler(direction, datagram, context):
    print(
        context.remote_address,
        len(datagram),
    )

    return datagram
```

The handler must not accidentally merge UDP packets.

If it returns:

```python
None
```

drop that datagram.

If it returns bytes:

send exactly one resulting UDP datagram.

---

# 22. UDP CONTEXT

Expose useful metadata:

```python
context.remote_ip
context.remote_port
context.tunnel_id
context.flow_id
context.direction
context.protocol
```

Do not expose internal secrets.

---

# 23. UDP LARGE-DATA REQUIREMENT

The existing `>=5 GB` requirement refers to total service transfer and MUST apply to UDP as well.

This does NOT mean one 5 GB UDP datagram.

Test a UDP workload whose aggregate transferred data exceeds:

```text
5 GB
```

For example:

```text
~1400-byte datagrams
continuously transferred
until >6 GB aggregate payload
```

Verify:

```text
datagrams sent
datagrams received
bytes sent
bytes received
loss
duplication
reordering
CPU
RSS
```

UDP tests must account for the fact that packet loss is legitimate under sufficiently stressed networks.

Under a controlled localhost/network-namespace environment with no intentional loss, expected loss should be effectively zero.

---

# 24. UDP PERFORMANCE TESTS

Benchmark:

```text
packets/sec
Mb/s
CPU usage
RAM usage
packet loss
packet duplication
packet reordering
latency
p50 latency
p95 latency
p99 latency
```

Test datagram sizes such as:

```text
64 B
256 B
512 B
1200 B
1400 B
4 KB
16 KB
```

Larger sizes should specifically test fragmentation behavior.

---

# 25. UDP FAILURE TESTS

Add tests for:

```text
agent disconnect during UDP flow
agent reconnect
broker restart
consumer disappears
local UDP service unavailable
flow timeout
many source addresses
many source ports
flow table exhaustion
datagram flood
oversized datagram
zero-length datagram
rapid flow churn
duplicate packets
packet reordering
packet loss
QUIC reconnect
QUIC path migration where supported
NAT rebinding
IPv4
IPv6 where available
```

---

# 26. UDP ABUSE PROTECTION

UDP is particularly vulnerable to amplification and spoofing-related abuse.

Implement safeguards.

At minimum:

```text
max packets/sec per tunnel
max packets/sec per source
max bytes/sec where configured
max UDP flows per tunnel
global max UDP flows
flow creation rate limits
datagram size limits
idle flow expiration
```

TunnelMate must not become a generic UDP reflection/amplification service.

Design open-mode UDP forwarding carefully.

---

# 27. SOURCE ADDRESS MODEL

Document an important limitation:

The local UDP service will normally see the TunnelMate agent as its packet source rather than the original Internet IP.

TunnelMate metadata must still know:

```text
original remote IP
original remote port
```

so the agent can route replies correctly.

Do not prepend proprietary metadata to the UDP payload sent to the local service because that would break arbitrary UDP applications.

Instead maintain an agent-side NAT-style mapping.

Conceptually:

```text
remote peer A
      │
      ▼
flow A
      │
agent local UDP socket A
      │
      ▼
service
```

Using independent local sockets per active remote flow is acceptable if resource limits are enforced.

Alternatively implement an equivalent mapping that preserves response routing.

Document the selected design.

---

# 28. UDP AGENT SOCKET STRATEGY

Evaluate two approaches.

## Option A — socket per flow

```text
remote A → local UDP socket A → service
remote B → local UDP socket B → service
```

Advantages:

```text
simple reply mapping
standard UDP application compatibility
```

Costs:

```text
more file descriptors
```

## Option B — shared socket with mapping

Use if it can reliably distinguish service replies.

Choose the design that provides the strongest arbitrary-UDP compatibility while remaining within VPS/agent resource limits.

Document the decision.

---

# 29. UDP NAT REBINDING

A mobile/client network may change its external source port.

Do not blindly treat all changed source addresses as the same client.

Use explicit closed peer/session identities where available.

For open raw UDP tunnels, a new source tuple generally creates a new UDP flow.

---

# 30. UPDATED BROKER RESPONSIBILITIES

`tunnelmated` must now implement:

```text
TCP listeners
UDP listeners

TCP stream association
UDP flow association

TCP backpressure
UDP datagram queues

TCP metrics
UDP metrics

TLS TCP data transport
encrypted UDP tunnel transport
```

Keep TCP and UDP internals modular.

Suggested modules:

```text
broker_tcp.c
broker_udp.c
broker_control.c
broker_tls.c
broker_quic.c
broker_metrics.c
```

Exact filenames may differ.

---

# 31. UDP QUEUES MUST BE BOUNDED

Because UDP cannot use TCP-style backpressure directly, use bounded packet queues.

Example:

```text
max_udp_queue_packets
max_udp_queue_bytes
```

When the queue is full:

```text
drop according to documented policy
increment drop metric
```

Never allocate unlimited packet queues.

---

# 32. UDP METRICS

Expose:

```text
udp_tunnels_online
udp_flows_active

udp_datagrams_rx
udp_datagrams_tx

udp_bytes_rx
udp_bytes_tx

udp_dropped_queue_full
udp_dropped_oversize
udp_dropped_rate_limit
udp_dropped_no_flow

udp_flow_created
udp_flow_expired

udp_transport_errors
```

Include per-tunnel counters where practical.

---

# 33. ADMIN UI

Show protocol explicitly.

Example tunnel table:

| ID    | Protocol | Scope | Address | Service | State  | Connections/Flows |  RX |  TX |
| ----- | -------- | ----- | ------- | ------- | ------ | ----------------: | --: | --: |
| tun_a | TCP      | open  | :24117  | YOLO    | online |                 4 | ... | ... |
| tun_b | UDP      | open  | :24118  | game    | online |                27 | ... | ... |

For TCP display:

```text
active streams
```

For UDP display:

```text
active flows
```

---

# 34. TOPOLOGY VIEW

Represent protocol appropriately.

For example:

```text
                    BROKER
                /             \
           TCP tunnel      UDP tunnel
               │                │
           stream ×3        flow ×28
               │                │
              API          Game Server
```

---

# 35. UPDATED FAILURE CASES

`docs/failure-cases.md` must separately cover:

```text
TCP failures
UDP failures
QUIC/datagram transport failures
```

Do not treat UDP connection behavior as if it were TCP.

---

# 36. NAT TEST

The NAT integration environment must test both:

```text
TCP service behind NAT
UDP service behind NAT
```

For UDP, demonstrate:

```text
public UDP client
        │
        X cannot directly reach NAT service
        │
        ▼
TunnelMate public UDP address
        │
        ▼
local service behind NAT
```

Use an echo service or another deterministic UDP server for testing.

---

# 37. DNS-LIKE TEST

Add a request/reply UDP test resembling DNS behavior:

```text
short request
short response
many independent remote clients
```

This validates correct flow mapping.

No requirement exists to implement an actual DNS server.

---

# 38. REAL-TIME UDP TEST

Add a continuous stream test resembling:

```text
telemetry
game networking
RTP-like traffic
```

Measure:

```text
latency
jitter
loss
reordering
```

This is important because a UDP tunnel that merely achieves throughput while adding severe HOL latency is not acceptable.

---

# 39. UPDATED ACCEPTANCE CRITERIA

TunnelMate is incomplete unless all four combinations work:

```text
OPEN TCP
CLOSED TCP
OPEN UDP
CLOSED UDP
```

## Open TCP

```text
raw TCP client
    ↓
public broker port
    ↓
private TCP service
```

## Closed TCP

```text
TCP app
    ↓
tunnelmate-peer
    ↓
authenticated broker
    ↓
private TCP service
```

## Open UDP

```text
raw UDP client
    ↓
public broker UDP port
    ↓
private UDP service
```

Datagram boundaries must be preserved.

## Closed UDP

```text
UDP app
    ↓
local tunnelmate-peer UDP port
    ↓
authenticated encrypted tunnel
    ↓
private UDP service
```

---

# 40. UPDATED SDK ACCEPTANCE

The following must work:

```python
tcp = tunnelmate.new(
    broker_url,
    {
        "host": "127.0.0.1",
        "port": 8000,
        "protocol": "tcp",
        "scope": "open",
        "service_name": "HTTP API",
        "service_id": "api",
        "llms": "http://127.0.0.1:8000/llms.txt",
    },
)
```

and:

```python
udp = tunnelmate.new(
    broker_url,
    {
        "host": "127.0.0.1",
        "port": 5000,
        "protocol": "udp",
        "scope": "open",
        "service_name": "UDP Service",
        "service_id": "udp-service",
        "llms": "http://127.0.0.1:8080/llms.txt",
    },
)
```

---

# 41. UPDATED FUTURE FEATURES

Remove UDP from the future-extension list.

Future extensions may still include:

```text
HTTP hostname routing
custom domains
multi-broker federation
WebSocket-native endpoints
mTLS
accounts
reserved ports
bandwidth quotas
advanced QUIC migration
multi-path QUIC
HTTP/3 service routing
```

But **UDP itself is a v1 requirement**.

---

# FINAL UDP DESIGN REQUIREMENT

The implementation should conceptually provide:

```text
                          TunnelMate VPS
                   ┌────────────────────────┐
                   │                        │
 TCP Internet ────►│ TCP Relay              │
                   │        │               │
                   │        │ TLS           │
                   │        ▼               │
                   │     TCP Agent          │
                   │                        │
 UDP Internet ────►│ UDP Relay              │
                   │        │               │
                   │        │ QUIC Datagram │
                   │        ▼               │
                   │     UDP Agent          │
                   │                        │
                   └────────────────────────┘
```

The overarching rule is:

**TCP must retain TCP stream semantics.**

**UDP must retain UDP datagram semantics.**

Do not reduce both protocols to a single stream abstraction merely because that simplifies implementation.
