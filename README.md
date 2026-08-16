# TunnelMate

TunnelMate is a capability-based reverse-tunnelling service for TCP and UDP.
A C/libuv broker relays encrypted traffic for devices behind NAT; a separate
FastAPI/SQLite process provides anonymous tunnel creation, leases, a generic
service registry, and a small operations console. No account or global API key
is needed to create a tunnel.

## Build and test

Ubuntu/Debian needs CMake, a C17 compiler, pkg-config, libuv, OpenSSL 3.2+, and
Python 3.11+.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

python3 -m venv .venv
.venv/bin/pip install -e './control[dev]' -e './python-sdk[dev]'
.venv/bin/pytest control/tests python-sdk/tests
TUNNELMATE_BUILD_DIR="$PWD/build" .venv/bin/pytest tests/integration
```

Use `-DTUNNELMATE_SANITIZE=ON` for ASan/UBSan. The integration tests launch
real broker, agent, and peer binaries and cover open/closed TCP/UDP, bad closed
tokens, datagram boundaries, large payload integrity, and teardown.

## Quick server install

Point a DNS name at the VPS, open TCP 443/7000/20000-40000 and UDP
20000-40000, then run from a checkout:

```bash
sudo TUNNELMATE_PUBLIC_HOST=tunnel.example.com \
  TUNNELMATE_ADMIN_PASSWORD='a unique long password' \
  deployment/scripts/tunnelmate-install
```

The bootstrap self-signs the data-plane certificate only when none is
supplied; replace it with a publicly trusted certificate before production.
Put the included Caddyfile in front of the API for HTTPS.

## Python producer

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
with tunnelmate.new("https://tunnel.example.com", conf) as tunnel:
    tunnel.announce()
    print(tunnel.peer_address)
    tunnel.wait()
```

Closed consumers use `tunnelmate.connect(...)` or:

```bash
tunnelmate-peer connect tunnel://tunnel.example.com:7000/tun_ID \
  --token-file ./token --listen 127.0.0.1:9000 --protocol tcp
```

Start with [the quickstart](docs/quickstart.md), then see
[architecture](docs/architecture.md), [deployment](docs/deployment.md),
[security](docs/security.md), and [testing](docs/testing.md). The canonical
wire description is [protocol/protocol.md](protocol/protocol.md).

License: GPL-3.0, see [LICENSE](LICENSE).
