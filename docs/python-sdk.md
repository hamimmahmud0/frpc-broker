# Python SDK

```bash
pip install ./python-sdk
```

The SDK does **not** reimplement the tunnel protocol. It talks to the control
API over HTTPS and supervises the compiled C agent, so payload bytes stay on
the C fast path. You should not need to understand asyncio to expose a port.

Point it at the binaries if they are not on `PATH`:

```bash
export TUNNELMATE_AGENT_BINARY=/usr/local/sbin/tunnelmate-agent
export TUNNELMATE_PEER_BINARY=/usr/local/sbin/tunnelmate-peer
```

## Creating a tunnel

Either a plain dict or the typed model — both validate identically.

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

tunnel = tunnelmate.new("https://broker.example.com", conf)
tunnel.announce()
tunnel.start()
print(tunnel.peer_address)      # tcp://203.0.113.10:20000
```

```python
from tunnelmate import TunnelConfig, new

conf = TunnelConfig(
    host="127.0.0.1", port=5675,
    protocol="udp", scope="open",
    service_name="UDP Telemetry Service",
    service_id="telemetry-v1",
    llms="https://example.com/llms.txt",
    attributes={"format": "binary"},
)
tunnel = new("https://broker.example.com", conf)
```

### `TunnelConfig`

| Field | Default | Meaning |
|---|---|---|
| `host`, `port` | `127.0.0.1`, — | The local service to expose. |
| `protocol` | `tcp` | `tcp` or `udp`; anything else is rejected at validation. |
| `scope` | `open` | `open` (public port) or `closed` (peer + token). |
| `shared_token` | generated | Closed mode; 16–256 characters if supplied. |
| `service_name`, `service_id` | — | Registry metadata. `service_id` should be stable. |
| `llms` | — | Required to announce; must be an `http(s)` URL. |
| `attributes` | `{}` | Arbitrary JSON within the server's limits. |
| `verify_ca` | `True` | Certificate and hostname verification. |
| `ca_path` | system store | CA bundle for a private CA. |
| `agent_binary` | `PATH`/env | Explicit agent path. |
| `log_level` | `info` | `debug`, `info`, `warn`, `error`. |

A `service_id` does not imply a protocol — DNS over TCP and DNS over UDP are
two tunnels sharing an id, distinguished by `protocol` in the announcement.

## Lifecycle

```python
tunnel.start()          # launch the agent and connect to the broker
tunnel.stop()           # stop the agent, remove the temporary config
tunnel.wait(timeout=60) # block while the agent runs
tunnel.delete()         # delete the tunnel server-side (releases the port)

tunnel.announce()       # publish to the registry
tunnel.unannounce()     # remove the listing

tunnel.status()         # server-side state
tunnel.stats()          # byte and connection counters
tunnel.renew()          # extend the lease (automatic while running)
tunnel.rotate_token()   # new shared token, returned once
```

Properties: `tunnel_id`, `peer_address`, `management_secret`, `shared_token`.

Prefer the context manager — it stops the agent and removes the credential file
even if the body raises:

```python
with tunnelmate.new(broker_url, conf) as tunnel:
    tunnel.announce()
    tunnel.start()
    print(tunnel.peer_address)
    tunnel.wait()
```

The lease renews on a background thread while the tunnel runs, so a long-lived
service does not expire underneath you.

## Consuming a closed tunnel

```python
peer = tunnelmate.connect(
    "tunnel://203.0.113.10:7000/tun_ID",
    token="the-shared-token",
    local_port=9000,
)
peer.start()
# the application now connects to 127.0.0.1:9000
```

`connect()` also takes `local_host`, `protocol`, `ca_path` and `verify_ca`. It
starts the C peer with the token in a 0600 file and removes it on stop.

Equivalent CLI:

```bash
tunnelmate-peer connect tunnel://203.0.113.10:7000/tun_ID \
  --token-file ./token --listen 127.0.0.1:9000 --protocol tcp
```

## Message handlers

```python
def handler(direction, data, context):
    # direction: "peer_to_service" | "service_to_peer"
    return data          # bytes  -> forward (possibly modified)
                         # None   -> drop this chunk

tunnel.set_message_handler(handler)
```

This changes the topology. Normally payload never touches Python:

```text
peer  ↕  C broker  ↕  C agent  ↕  service
```

With a handler, the agent points at a local Python proxy instead:

```text
peer  ↕  C broker  ↕  C agent  ↕  Python proxy  ↕  service
```

That is the documented cost of asking for interception, and the reason handlers
are off by default. **Leave them disabled for large or high-throughput
transfers** — see [performance.md](performance.md) for the measured difference.

### TCP versus UDP handlers

TCP is a byte stream with no inherent message boundaries, so a handler receives
arbitrary **chunks**. Do not assume one chunk is one application message.

For UDP a handler receives exactly **one datagram** per call, and returning
bytes sends exactly one datagram. Datagrams are never merged. `context` exposes
`remote_ip`, `remote_port`, `tunnel_id`, `flow_id`, `direction` and `protocol`
— never secrets.

Changing a chunk's length or content can break the application protocol running
inside it. That is your responsibility, not something TunnelMate can check.

## CLI

```bash
tunnelmate new       # create a tunnel
tunnelmate start     # run the agent
tunnelmate connect   # consume a closed tunnel
tunnelmate announce  # publish to the registry
tunnelmate status    # show state
```

## Handling secrets

Secrets are never passed on the command line — other local users can read
`/proc/PID/cmdline`. The SDK writes a 0600 config file for the agent and a 0600
token file for the peer, then removes them on stop.

Creation secrets are returned exactly once. `tunnel.rotate_token()` and the
`rotate-agent-secret` endpoint issue new ones and invalidate the old
immediately, so update any running agent alongside the call.

## Errors

Everything raises `TunnelMateError` with the server's `code`, `message` and
`request_id`, so a failure can be correlated with the server log.

```python
from tunnelmate import TunnelMateError

try:
    tunnel.start()
except TunnelMateError as exc:
    print("tunnel failed:", exc)
```
