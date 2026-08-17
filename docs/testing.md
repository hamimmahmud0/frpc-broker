# Testing

## Layout

```text
common/tests/           C unit tests: framing, malformed bounds, crypto, config
control/tests/          API: lifecycle, ownership, registry, health, admin auth
python-sdk/tests/       SDK config, factories, message-handler proxy
tests/harness.py        shared process management (real binaries, no mocks)
tests/integration/      the four acceptance modes + half-close + large streams
tests/failure/          fault injection; mirrors docs/failure-cases.md
tests/security/         threat-model coverage, control plane and data plane
tests/load/             concurrency, UDP latency/throughput, benchmark
tests/nat/              root-only network-namespace NAT scenario
```

Nothing in `tests/` mocks the data path. The harness launches the real
`tunnelmated`, `tunnelmate-agent` and `tunnelmate-peer` with real TLS and DTLS,
so a passing suite means those binaries behaved, not that a stub did.

## Running

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

python3 -m venv .venv
.venv/bin/pip install -e './control[dev]' -e './python-sdk[dev]'
export TUNNELMATE_BUILD_DIR=$PWD/build

.venv/bin/pytest tests control/tests python-sdk/tests
.venv/bin/ruff check control python-sdk tests
```

The default run takes about 90 seconds and covers 112 tests.

## Sanitizers

```bash
cmake -S . -B build-sanitize -DTUNNELMATE_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-sanitize --parallel
TUNNELMATE_BUILD_DIR=$PWD/build-sanitize .venv/bin/pytest tests
```

ASan and UBSan run against the same integration, failure, security and load
suites — not just unit tests, because the bugs worth catching live in the
relay's lifetime handling. Two real defects were found this way: a null `tm_io`
dereference when one relay leg outlived the other, and the use-after-free
window when a tunnel was deleted while a `uv_close` was still in flight.

## Extended tests

Opt-in because they take minutes and move gigabytes. They are mandatory before
a release, not optional.

```bash
# 6 GiB through open and closed TCP, hash verified, no disk spooling
TUNNELMATE_LARGE_BYTES=6442450944 .venv/bin/pytest tests/integration -s -k large

# 6 GiB aggregate UDP in ~1400-byte datagrams
TUNNELMATE_UDP_LARGE_BYTES=6442450944 .venv/bin/pytest tests/load -s -k aggregate

# 256 simultaneous connections
TUNNELMATE_LOAD_EXTENDED=1 .venv/bin/pytest tests/load -s -m extended

# comparison table against direct localhost
tests/load/benchmark.py --bytes 512MiB
```

Constrained machines can scale the concurrency suites down with
`TUNNELMATE_LOAD_TUNNELS`, `TUNNELMATE_LOAD_CONNECTIONS` and
`TUNNELMATE_LOAD_FLOWS`.

## NAT scenario

```bash
sudo tests/nat/nat_scenario.sh build
```

Builds three network namespaces — public peer, VPS/router, private host — with
MASQUERADE for private egress and an explicit DROP for inbound traffic to the
private subnet. It asserts that the peer namespace **cannot** reach the private
service directly over TCP or UDP, that both reach it through TunnelMate, and
that UDP datagram sizes survive the path unchanged. Root only; the ordinary
suite exercises the same outbound-only topology on loopback.

## What each suite is for

| Suite | Question it answers |
|---|---|
| `common/tests` | Does the parser reject malformed and oversized input before allocating? |
| `control/tests` | Does anonymous creation work, and is ownership enforced? |
| `tests/integration` | Do open/closed × TCP/UDP actually relay bytes end to end? |
| `tests/failure` | Does each documented failure behave as documented? |
| `tests/security` | Does each threat-model entry hold against a real attempt? |
| `tests/load` | Does it stay bounded and fast enough under concurrency and volume? |
| `tests/nat` | Is the private host genuinely unreachable except through the tunnel? |

## Writing tests here

Use the `broker` fixture for a default two-port broker, or `broker_factory` when
a scenario needs specific limits:

```python
def test_something(broker_factory):
    broker = broker_factory(settings={"broker.udp_max_datagram_size": 1400})
    tunnel = broker.create_tunnel("my-test", proto="udp")
    start_agent(broker, tunnel, service_port, "udp")
```

Teardown kills every tracked process and fails the test if the broker exited
with anything other than 0 or SIGTERM, so a crash cannot pass unnoticed even if
the assertions were satisfied.

When a test fails, find the cause rather than loosening the assertion. Every
bug listed in `docs/failure-cases.md` was found by a test that looked like it
was "just being flaky".
