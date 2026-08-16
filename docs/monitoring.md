# Monitoring

Poll `/health/live`, `/health/ready`, and `/v1/status`. Watch tunnel/stream/port
counts, RX/TX, failed auth, reconnects, protocol errors, and UDP drops. Host
alerts should cover CPU saturation, RSS, free disk, open FDs, packet loss, and
service restart rate. The admin topology refreshes every ten seconds. Metrics
are counters held in broker memory and reset on restart; use an external
scraper if historical retention is required, with a bounded retention policy.
