# Performance and large streams

The hot path is C/libuv/OpenSSL and never writes payloads to disk. Backpressure
pauses upstream reads at a 256 KiB high watermark and resumes below 128 KiB.
Run `tests/load/large_stream.py` with a hash server behind an open TCP tunnel;
the default client transfers 6 GiB as deterministic generated blocks, sends a
FIN, and compares the returned SHA-256. Set `--bytes` for CI-sized runs.

Benchmark direct localhost, open, closed, and handler endpoints with the same
payload and host state. Record wall time, bytes/s, `pidstat` CPU, and
`/proc/PID/status` peak RSS. Do not compare UDP throughput with TCP or claim
results across hardware. Measured acceptance results belong in the release
completion report rather than being baked into this document.
