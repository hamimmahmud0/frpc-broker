# Troubleshooting

- Readiness 503: verify broker service and `/run/tunnelmate/broker.sock`
  ownership, then inspect both journals.
- Agent register rejected: tunnel may be expired/disabled or its secret was
  rotated; create a fresh 0600 config.
- Certificate error: SAN must match `broker_host`; install the correct CA. Do
  not work around production failures with `verify_ca=false`.
- Public connection refused: check agent online state, allocated TCP/UDP
  firewall rule, listener limit, and local service.
- UDP timeout: confirm both UDP firewall direction and the API-returned public
  UDP port; keep datagrams at or below configured 1400 bytes.
- Port exhaustion: reduce live leases or enlarge the unprivileged range and
  firewall consistently.
- SQLite errors: check disk, owner/mode, WAL files, and `PRAGMA integrity_check`.
