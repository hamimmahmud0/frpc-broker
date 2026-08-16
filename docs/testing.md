# Testing

```bash
cmake -S . -B build-sanitize -DTUNNELMATE_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-sanitize --parallel
ctest --test-dir build-sanitize --output-on-failure
.venv/bin/pytest control/tests python-sdk/tests
TUNNELMATE_BUILD_DIR=$PWD/build-sanitize .venv/bin/pytest tests/integration
.venv/bin/ruff check control python-sdk tests
```

C tests cover framing, malformed bounds, crypto/config helpers, and coalesced
frames. Python tests cover anonymous lifecycle/ownership, arbitrary registry
attributes/search, health, admin auth/CSRF and SDK behavior. Integration uses
real TLS/DTLS binaries for all four open/closed TCP/UDP modes. Extended tests
run the generated 6 GiB hash transfer and constrained concurrency/load. Network
namespace NAT simulation requires root and is described in `tests/nat/README`.
