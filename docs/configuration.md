# Configuration

`deployment/broker.conf` is the complete conservative VPS example. Important
groups are listen/control/public ports; TLS certificate/key and broker HMAC
key; tunnel/stream/pending limits; heartbeat/handshake/idle/shutdown timers;
and UDP datagram/flow/packet/queue limits.

The API uses `TUNNELMATE_*` variables documented in `deployment/example.env`.
Production requires a stable 32+ character secret key. Agent configs use
`agent.broker_host`, `broker_port`, `broker_udp_port`, `protocol`, `tunnel_id`,
`agent_secret`, local host/port, CA path, verification, reconnect/heartbeat
timers, and UDP limits. The SDK writes this config with mode 0600.
