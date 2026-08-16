# Threat model

Internet clients, anonymous API callers, and announcement text are untrusted.
The local Unix socket and host administrator are trusted; a compromised agent
can access only its own configured local service and tunnel.

| Threat | Control |
|---|---|
| malformed/oversized frames | pre-allocation bounds, version checks, parser tests |
| token guessing/replay/leakage | high-entropy scoped capabilities, TLS/DTLS, HMAC storage, constant-time checks, rotation |
| port/FD/connection exhaustion | fixed range and global/per-tunnel/rate limits, deadlines |
| slow peer/service and memory exhaustion | libuv backpressure, 256 KiB watermarks, bounded UDP queues |
| SQL injection/XSS/log injection | parameters, autoescaping, structured bounded logs |
| SSRF | URLs are structurally validated and never fetched |
| CSRF/admin brute force | CSRF token, secure cookie, scrypt, login rate limit |
| UAF/double free/integer overflow | explicit libuv close ownership, overflow guards, ASan/UBSan integration tests |
| TLS downgrade/bad certificate | minimum TLS/DTLS 1.2, TLS 1.3 preference, default verification |
| payload/disk disclosure | no inspection or spooling; no payload logging |

Token replay by someone who already possesses a capability is inherent to a
bearer-capability design until rotation. End-to-end encryption from peer to
agent (without broker plaintext) and QUIC DATAGRAM are future extensions.
