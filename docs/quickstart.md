# Quickstart

Build and install the server as described in the README. Verify the independent
processes with `systemctl status tunnelmated tunnelmate-api` and
`curl https://tunnel.example.com/health/ready`.

Install the client package and make the C binaries discoverable:

```bash
python3 -m venv .venv
.venv/bin/pip install ./python-sdk
export TUNNELMATE_AGENT_BINARY=/usr/local/sbin/tunnelmate-agent
export TUNNELMATE_PEER_BINARY=/usr/local/sbin/tunnelmate-peer
```

Run a local TCP service, use the producer example from the README, then connect
to the returned `tcp://host:port`. For UDP set `protocol="udp"` and point the
local port at a UDP service. Closed tunnels return a shared token once; store it
in a 0600 file and give it only to intended consumers.

Clients verify certificates and hostnames by default. A development CA can be
passed with `ca_path`; disabling verification must be explicit and must not be
used for public deployments.
