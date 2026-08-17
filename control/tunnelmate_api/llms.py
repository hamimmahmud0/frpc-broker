"""The /llms.txt document.

Written so that a reader arriving with nothing but this URL can get a working
tunnel: install the software, obtain the certificate, create a tunnel, run the
agent and verify it, without fetching any other page. It is generated rather
than static because the host, ports, source URL and limits differ per
deployment, and a reader following stale values would build wrong requests.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Settings

# scripts/build-release.sh names its tarballs like
# tunnelmate-0.1.0-linux-x86_64.tar.gz.
_RELEASE_TARBALL = re.compile(r"^tunnelmate-(?P<version>[^/]+?)-linux-(?P<arch>[^/]+)\.tar\.gz$")


def _published_releases(release_dir: Path) -> tuple[str | None, list[str]]:
    """The version and architectures this deployment actually has on disk.

    Read at render time rather than hard-coded, because a version baked into
    the document would start naming a download that 404s the moment the
    operator publishes a different build — which is the failure this whole
    document exists to avoid.
    """
    try:
        names = sorted(p.name for p in release_dir.iterdir() if p.is_file())
    except OSError:
        return None, []
    version: str | None = None
    arches: list[str] = []
    for name in names:
        match = _RELEASE_TARBALL.match(name)
        if not match:
            continue
        # Mixed versions in one directory would make the example ambiguous;
        # the newest sorts last, so keep taking it.
        version = match["version"]
        arches.append(match["arch"])
    return version, sorted(set(arches))


def _download_steps(base_url: str, version: str, arches: list[str]) -> str:
    """Step 1 when this deployment actually publishes binaries."""
    listing = "\n".join(f"  tunnelmate-{version}-linux-{arch}.tar.gz" for arch in arches)
    return f"""### Step 1 — get the binaries

This broker publishes pre-built binaries, so there is nothing to compile.
Currently available:

```
{listing}
```

Pick the one matching `uname -m` — `x86_64` for ordinary PCs and servers,
`aarch64` for ARM machines such as a Raspberry Pi or an ARM cloud instance:

```bash
ARCH=$(uname -m)
curl -fsSL {base_url}/v1/download/tunnelmate-{version}-linux-$ARCH.tar.gz | tar xz
cd tunnelmate-{version}-linux-$ARCH
sudo install -m 0755 tunnelmate-agent tunnelmate-peer /usr/local/bin/
```

To check the download first, the checksums are published beside it:

```bash
curl -fsSL {base_url}/v1/download/SHA256SUMS -o SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

`GET /v1/downloads` returns the same list as JSON, each entry carrying a
`name`, a `size` and an absolute `url` — use that if you are automating this.

The tarball holds three binaries:

```
tunnelmate-agent    publish a service        <- you need this
tunnelmate-peer     consume a closed tunnel  <- and maybe this
tunnelmated         the broker (only a server operator needs it)
```

They are statically linked against musl, so there is no libuv, no OpenSSL and
no glibc version to match — any Linux kernel on that architecture runs them.
Confirm yours did:

```bash
tunnelmate-agent -c /dev/null; echo "exit $?"   # prints a config error: it runs
```

If your architecture is not in the list above, build from source with step 2.
Otherwise skip to step 3."""


def _no_downloads_notice(base_url: str) -> str:
    """Step 1 when the operator has published nothing.

    Saying so plainly beats printing a download command that 404s: a reader who
    tries the URL and fails has no way to tell a broken deployment from a
    deliberate one.
    """
    return f"""### Step 1 — get the binaries

This deployment publishes no pre-built binaries — `GET {base_url}/v1/downloads`
returns an empty list — so build them from source with step 2. That is a
choice by this broker's operator, not a fault; other deployments may publish
them."""


def render(settings: Settings, base_url: str) -> str:
    """Build llms.txt for this deployment.

    ``base_url`` is the origin the caller reached us on, so every example is
    copy-pasteable rather than pointing at a host the agent cannot resolve.
    """
    host = settings.public_host
    control_port = settings.broker_control_port
    lease_hours = settings.lease_seconds // 3600
    src = settings.source_url
    # pip cannot install a subdirectory of a repository without the fragment,
    # and the .git suffix is what pip's VCS handler expects.
    sdk_spec = f"git+{src}.git#subdirectory=python-sdk"
    version, arches = _published_releases(settings.release_dir)
    download_section = (
        _download_steps(base_url, version, arches) if version else _no_downloads_notice(base_url)
    )
    how_to_get_it = (
        "The binary is written in C, but this broker publishes pre-built ones — "
        "statically linked, so they run on any Linux of the right architecture "
        "with nothing installed alongside them. Step 1 downloads one; building "
        "from source is offered as step 2 and is not required."
        if version
        else "The binary is written in C and this deployment publishes no "
        "pre-built ones, so you compile it from source once (about a minute). "
        "Step 2 does exactly that."
    )

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
Source code: {src}
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

## What you have to install

Read this before starting, because it decides how much work you are in for.

**To publish a service you must run the `tunnelmate-agent` binary.** There is
no pure-Python, browser or curl-only way to do it: the HTTP API creates the
tunnel, but only the agent can carry traffic. {how_to_get_it}

**To consume an `open` tunnel you install nothing.** It is an ordinary public
TCP or UDP address. Use curl, a browser, psql, ssh, netcat, anything.

**To consume a `closed` tunnel you need the `tunnelmate-peer` binary**, which
ships alongside the agent, plus the tunnel's shared token.

The Python SDK is a convenience wrapper that supervises those binaries. It does
not replace them and installing it alone is not enough.

### Note on the package name

`pip install tunnelmate` installs an **unrelated third-party package** of the
same name from PyPI. It is not this project and will not work. Always install
from source:

```bash
pip install "{sdk_spec}"
```

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

## Setup, step by step

This is the complete path from a bare machine to a public address. Every
command is meant to be run as-is. The example exposes an HTTP service listening
on `127.0.0.1:5675`; substitute your own host and port.

{download_section}

### Step 2 — build from source instead (optional)

Only needed if the download above did not cover you. You need a Linux machine
(or WSL) with outbound Internet access, and:

  - a C17 compiler, CMake 3.16+, pkg-config
  - libuv development headers
  - **OpenSSL 3.2 or newer** development headers
  - Python 3.11+ (only if you want the SDK)

The OpenSSL floor is the one that catches people out. Ubuntu 24.04 LTS and
Debian 12 ship OpenSSL 3.0, and the build stops at the configure step with a
clear message. Ubuntu 24.10+, Debian 13+ and current Fedora/Arch are fine.
Check with `openssl version` before starting. If yours is older, download a
release from step 1 instead of upgrading OpenSSL.

On Debian or Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config \\
    libuv1-dev libssl-dev git python3 python3-venv ca-certificates
```

On Fedora:

```bash
sudo dnf install -y gcc cmake pkgconf-pkg-config libuv-devel openssl-devel git python3
```

Then:

```bash
git clone {src}.git
cd frpc-broker
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

That produces three binaries:

```
build/agent/tunnelmate-agent    publish a service        <- you need this
build/peer/tunnelmate-peer      consume a closed tunnel  <- and maybe this
build/broker/tunnelmated        the broker (only a server operator needs it)
```

Put the two client binaries on your PATH:

```bash
sudo install -m 0755 build/agent/tunnelmate-agent build/peer/tunnelmate-peer /usr/local/bin/
```

If it fails at `find_package(OpenSSL 3.2 REQUIRED)`, your OpenSSL is too old.
If it fails on libuv, `libuv1-dev` is missing.

Add `-DTUNNELMATE_STATIC=ON` to produce the same portable binaries this broker
publishes; that needs a musl toolchain and static libuv/OpenSSL, so it is for
whoever is building releases, not for a one-off local build.

### Step 3 — get the broker's certificate

The agent verifies the broker's TLS certificate, and this deployment may be
using a self-signed one, which your system trust store does not know. Fetch it
once:

```bash
curl -fsS {base_url}/v1/broker-certificate -o broker.crt
```

A 404 means the operator is using a publicly trusted certificate. In that case
skip this step and leave `agent.ca_path` out of the config below — the system
trust store already covers it.

Do not set `agent.verify_ca = false` to make an error go away. That disables
authentication of the broker entirely and lets anything on the path
impersonate it.

### Step 4 — create the tunnel

No credential is needed for this call.

```bash
curl -X POST {base_url}/v1/tunnels \\
  -H 'Content-Type: application/json' \\
  -d '{{"scope": "open", "protocol": "tcp"}}'
```

Response — **save it now, the secrets are never shown again**:

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

### Step 5 — write the agent config

Create `agent.conf`. Use mode 0600: it holds a secret, and other local users
can read command lines out of /proc, which is why nothing here is a flag.

```bash
touch agent.conf && chmod 600 agent.conf
```

```ini
agent.tunnel_id = tun_UE7u16l_zv67CsKO
agent.agent_secret = IlRysefG4qdNYuBE...
agent.local_host = 127.0.0.1
agent.local_port = 5675
agent.broker_host = {host}
agent.broker_port = {control_port}
agent.protocol = tcp
agent.verify_ca = true
agent.ca_path = /absolute/path/to/broker.crt
agent.log_level = info
```

`agent.local_host`/`agent.local_port` are **your** service. `agent.broker_host`
and `agent.broker_port` are this broker. Drop `agent.ca_path` if step 3
returned 404. For UDP see the UDP section — it needs one extra key.

### Step 6 — run the agent

The flag is `-c`, with one dash. `--config` is not accepted and exits 1.

```bash
tunnelmate-agent -c ./agent.conf
```

Leave it running. It reconnects on its own if the network or the broker blips.
At `info` level it logs the registration; use `agent.log_level = debug` if it
does not.

To run it as a service instead, use any supervisor you like — the binary stays
in the foreground and logs to stderr, so systemd, s6 or Docker all work
unmodified.

### Step 7 — verify

From anywhere on the Internet:

```bash
curl http://{host}:20000/
```

And ask the broker what it thinks:

```bash
curl {base_url}/v1/tunnels/tun_UE7u16l_zv67CsKO \\
  -H 'X-Tunnel-Management-Secret: 951rDXpuFGzWFWuE...'
```

`"online": true` means the agent is connected. If it is false, the agent is not
running or its secret is wrong; connections will be accepted and then closed.

### Step 8 — clean up

Deleting releases the public port and terminates live connections. Do it when
you are done; ports are a shared finite resource.

```bash
curl -X DELETE {base_url}/v1/tunnels/tun_UE7u16l_zv67CsKO \\
  -H 'X-Tunnel-Management-Secret: 951rDXpuFGzWFWuE...'
```

If you simply stop the agent without deleting, the tunnel lingers until its
{lease_hours}-hour lease expires, holding the port.

## The same thing with the Python SDK

The SDK does steps 4 to 8 for you, plus lease renewal and secret file hygiene.
You still need the binaries from step 1.

```bash
python3 -m venv .venv
.venv/bin/pip install "{sdk_spec}"
```

If the binaries are not on PATH, point at them:

```bash
export TUNNELMATE_AGENT_BINARY=/usr/local/bin/tunnelmate-agent
export TUNNELMATE_PEER_BINARY=/usr/local/bin/tunnelmate-peer
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
    "ca_path": "/absolute/path/to/broker.crt",   # omit if publicly trusted
}}

with tunnelmate.new("{base_url}", conf) as tunnel:
    tunnel.announce()
    print(tunnel.peer_address)
    tunnel.wait()
```

The context manager stops the agent, removes the temporary credential file and
leaves the tunnel deleted on exit. Consumers of a closed tunnel use
`tunnelmate.connect(peer_address, token=..., local_port=9000, ca_path=...)`.

Prefer the SDK over hand-rolling the flow: it handles renewal, secret hygiene
and teardown that are easy to get wrong.

## UDP tunnels

Create with `"protocol": "udp"`. The agent config needs one extra key that TCP
does not: `agent.broker_udp_port`, set to the `public_port` from the creation
response.

```ini
agent.tunnel_id = tun_...
agent.agent_secret = ...
agent.local_host = 127.0.0.1
agent.local_port = 5000
agent.broker_host = {host}
agent.broker_port = {control_port}
agent.broker_udp_port = 20001
agent.protocol = udp
agent.ca_path = /absolute/path/to/broker.crt
```

Control still runs over TCP on port {control_port}; datagrams travel over DTLS on
the UDP port. Keep payloads at or below 1400 bytes — larger datagrams are
dropped, never fragmented and never truncated.

## Private services (closed scope)

```bash
curl -X POST {base_url}/v1/tunnels \\
  -H 'Content-Type: application/json' \\
  -d '{{"scope": "closed", "protocol": "tcp"}}'
```

The response adds `shared_token`, and `peer_address` looks like
`tunnel://{host}:{control_port}/tun_ID`. No public port is opened.

The publisher side is identical to steps 6 to 8 above — same config, same
`-c` invocation. The difference is on the consumer side, which must run the
peer binary:

```bash
printf '%s' 'the-shared-token' > token && chmod 600 token

tunnelmate-peer connect tunnel://{host}:{control_port}/tun_ID \\
  --token-file ./token \\
  --listen 127.0.0.1:9000 \\
  --protocol tcp \\
  --ca ./broker.crt
```

The application then talks to `127.0.0.1:9000` as if the service were local.
Supply the token in a 0600 file, never as `--token` on the command line. A
wrong token reaches no service bytes at all.

For closed UDP the URL port is the tunnel's own allocated UDP port, not the
control port — use whatever `peer_address` you were given rather than
constructing it.

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
GET    /v1/broker-certificate                   broker TLS certificate, PEM
GET    /v1/downloads                            published release binaries
GET    /v1/download/{{name}}                      fetch one release file
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
| `CERTIFICATE_UNAVAILABLE` | 404 | No self-signed certificate is published; use the system trust store. |
| `DOWNLOAD_UNAVAILABLE` | 404 | No such release file. Re-read `/v1/downloads` for the current names. |

`request_id` is also returned as the `X-Request-ID` header. Quote it when
reporting a problem.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `usage: tunnelmate-agent [-c CONFIG]`, exit 1 | You used `--config`. It is `-c`. |
| Downloaded binary: `cannot execute binary file` | Wrong architecture. Match `uname -m` against `/v1/downloads`. |
| CMake stops on `OpenSSL 3.2` | System OpenSSL is older than 3.2. Download a release (step 1) instead. |
| Agent exits complaining about a certificate | Missing or wrong `agent.ca_path`. Redo step 3. |
| Agent runs but `"online": false` | Wrong `agent_secret` or `tunnel_id`, or it cannot reach port {control_port} outbound. |
| `online: true` but connections hang | The agent reaches the broker but not your service. Check `agent.local_host`/`local_port`. |
| Connection accepted then immediately closed | No agent is connected for that tunnel. |
| 404 on every management call | Wrong management secret. The API reports it identically to a missing tunnel. |
| Tunnel vanished after a day | The lease expired. Renew it, or let the SDK do it. |
| UDP works locally, drops over the tunnel | Datagram over 1400 bytes, or sending faster than the tunnel drains. |

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
- Do not install `tunnelmate` from PyPI. That name belongs to a different
  project. See "Note on the package name" above.

## Running your own broker

The same repository contains the server. On a fresh Debian/Ubuntu host:

```bash
git clone {src}.git && cd frpc-broker
sudo TUNNELMATE_PUBLIC_HOST=203.0.113.10 \\
     TUNNELMATE_ADMIN_PASSWORD='choose something long' \\
     deployment/scripts/tunnelmate-install
```

It builds everything, creates the system user, generates a development
certificate, installs both systemd units and verifies they are running. Open
the agent control port and the public port range on your firewall.

## Documentation

Full documentation is in `docs/` in the repository: quickstart, architecture,
protocol specification, API reference, Python SDK guide, announcements,
security model, threat model, deployment, configuration, operations,
monitoring, performance, failure cases, testing and troubleshooting.

Source: {src}
Protocol identifier: TunnelMate/1
Transport: TLS 1.2+ (1.3 preferred) for TCP, DTLS 1.2 for UDP
Licence: GPL-3.0
"""
