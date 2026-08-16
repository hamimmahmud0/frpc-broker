# Development

The repository is C17 plus Python 3.11+. Keep Python out of the normal payload
path. Every libuv handle owner must outlive its `uv_close` callback; every
client length is checked before allocation; queues require explicit bounds.
Never add secret/payload logging or disk spooling.

Use the sanitizer build and real integration tests for networking changes.
Update the normative protocol and an ADR for wire/security decisions. Format
Python with Ruff, retain `-Wall -Wextra -Wpedantic`, and keep new dependencies
small enough for the target 2 GB disk.
