# Quickstart

Two roles: whoever runs the VPS, and whoever exposes a service through it. If
someone else already runs a broker for you, skip to
[Expose a service](#expose-a-service).

## Install the server

On a fresh Ubuntu/Debian VPS, from a checkout:

```bash
sudo TUNNELMATE_PUBLIC_HOST=203.0.113.10 \
     TUNNELMATE_ADMIN_PASSWORD='choose something long and unique' \
     TUNNELMATE_API_PORT=9000 \
     deployment/scripts/tunnelmate-install
```

`TUNNELMATE_PUBLIC_HOST` is what appears in every `peer_address`, so set it to
what consumers will actually dial. A bare IP is fine and needs no DNS — the
installer picks the matching certificate SAN type automatically.

It builds and installs the binaries, creates the `tunnelmate` system user and
directories, sets up the venv, writes a 0640 environment file, generates a
development certificate, installs both systemd units, and then **verifies** the
services are genuinely running before reporting success. Re-running it is safe.

Confirm the two planes are independent processes:

```bash
systemctl status tunnelmated tunnelmate-api
curl http://127.0.0.1:9000/health/ready
# {"status":"ok","broker":"ok","database":"ok"}
```

Open the firewall for TCP 7000 (agent control) and TCP+UDP across the public
range in `broker.conf` (20000-40000 by default). Put the supplied Caddyfile in
front of the API for HTTPS; the API itself binds loopback only.

> The self-signed transport certificate is for development. Replace it with a
> publicly trusted certificate whose SAN matches your public host before anyone
> else relies on the service.

## Expose a service

```bash
python3 -m venv .venv
.venv/bin/pip install ./python-sdk
export TUNNELMATE_AGENT_BINARY=/usr/local/sbin/tunnelmate-agent
export TUNNELMATE_PEER_BINARY=/usr/local/sbin/tunnelmate-peer
```

With a service listening on `127.0.0.1:5675`:

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
    print(tunnel.peer_address)   # tcp://203.0.113.10:20000
    tunnel.wait()
```

Anyone can now reach your service at that address. No account was created and
no API key was used. The machine running this can sit behind NAT or CGNAT —
the agent only makes outbound connections.

The tunnel holds a 24-hour lease that the SDK renews while it runs. On exit the
context manager stops the agent and cleans up the temporary credential file.

### Without Python

```bash
curl -X POST https://broker.example.com/v1/tunnels \
  -H 'Content-Type: application/json' -d '{"scope":"open","protocol":"tcp"}'
```

Save the returned secrets — they are shown once. Write an agent config with
mode 0600 (see [configuration.md](configuration.md)) and run:

```bash
tunnelmate-agent --config /etc/tunnelmate/agent.conf
```

## UDP

Set `"protocol": "udp"` and point at a UDP service. You get a public UDP port,
and datagram boundaries are preserved exactly — one datagram in, one out, never
merged and never truncated. Keep payloads at or below 1400 bytes; larger ones
are dropped rather than silently split.

```python
conf = {
    "host": "127.0.0.1", "port": 5000,
    "protocol": "udp", "scope": "open",
    "service_name": "UDP Telemetry Service",
    "service_id": "telemetry-v1",
    "llms": "https://example.com/llms.txt",
    "attributes": {"format": "binary"},
}
```

## Private services

A closed tunnel has no public listener at all. Consumers need TunnelMate and
the shared token:

```python
conf = TunnelConfig(host="127.0.0.1", port=5675, scope="closed",
                    service_name="Private YOLO", service_id="private-yolo")
tunnel = tunnelmate.new(broker_url, conf)
tunnel.start()
print(tunnel.peer_address, tunnel.shared_token)   # store the token once
```

Consumer side:

```python
peer = tunnelmate.connect(tunnel_peer_address, token="...", local_port=9000)
peer.start()
# the application now uses 127.0.0.1:9000
```

or:

```bash
tunnelmate-peer connect tunnel://203.0.113.10:7000/tun_ID \
  --token-file ./token --listen 127.0.0.1:9000 --protocol tcp
```

Give the token only to intended consumers, in a 0600 file. A wrong token
reaches no service bytes at all.

## Find services

```bash
curl 'https://broker.example.com/v1/announce/search?service=yolo&attribute.size=n'
```

Filter by `service`, `service_id`, `scope`, `protocol`, `tunnel_id` and any
`attribute.NAME`. Each result carries an `llms` URL describing the service.

## Administration

`https://broker.example.com/admin`, with the username and password given at
install. The console shows tunnels, announcements, live topology and a system
panel (CPU, RAM, disk, broker RSS and descriptors, traffic rates) that updates
live.

## Certificates

Clients verify certificates and hostnames by default. For a private CA, pass
`ca_path`. Disabling verification is possible but must be explicit, and must
not be done for anything public — see [security.md](security.md).

## Next

[architecture.md](architecture.md) for how it fits together,
[api.md](api.md) for the full API,
[python-sdk.md](python-sdk.md) for the SDK,
[deployment.md](deployment.md) for production,
[troubleshooting.md](troubleshooting.md) when something misbehaves.
