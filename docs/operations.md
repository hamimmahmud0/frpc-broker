# Operations

Use `journalctl -u tunnelmated -u tunnelmate-api`; logs are structured and
journald should be capped (for example `SystemMaxUse=128M`). `/v1/status` and
the admin console show broker counters. Readiness checks both SQLite and IPC;
liveness checks only the API process.

Approximate TCP memory is 0.2-0.6 MiB per active paired stream depending on TLS
and queued bytes; watermarks cap application queues. UDP queues default to 256
packets per session and drop/count overflow. A 2 GB disk budget can reserve
~200 MB for OS/packages, ~150 MB for the app/venv, 128 MB journal, and a small
SQLite database; alert at 75%, investigate at 85%, and stop nonessential writes
at 95%. No payload should ever appear in `/tmp` or state directories.

SIGTERM gives the broker its configured grace interval. SIGKILL cannot be
graceful. Rotate an agent/token through the owner API; rotate the API and broker
HMAC root keys only during a planned capability migration.
