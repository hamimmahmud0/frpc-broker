# Deployment

The idempotent Ubuntu bootstrap is `deployment/scripts/tunnelmate-install`.
Set public DNS and a unique admin password as shown in the README. Replace the
development transport certificate with a certificate whose SAN matches the
broker host. Install Caddy with the supplied configuration for the HTTPS API.

Firewall ingress: TCP 443 and 7000, TCP+UDP 20000-40000. The API itself binds
only `127.0.0.1:8000`; broker IPC is a 0750 runtime directory and Unix socket.
Both services run as `tunnelmate` with systemd hardening and `LimitNOFILE`.
Configuration/secrets are root:tunnelmate 0640; persistent runtime data is in
`/var/lib/tunnelmate`.

For upgrades, build to a staging prefix, stop only the broker for the binary
swap, restart it, then restart the API so persisted unexpired tunnels are
restored. Existing data streams survive an API-only restart but not a broker
restart. Back up `control.db`, `hmac.key`, the API secret key, and certificates;
never back up tunnel payloads because none exist on disk.
