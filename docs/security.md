# Security

TLS is mandatory for TCP agent/peer links and DTLS for UDP-aware endpoints.
Certificate and hostname verification are on by default. Development bypasses
are explicit. Tunnel capabilities are generated from the OS CSPRNG, returned
once, stored as keyed HMACs, and compared in constant time. The SDK avoids
secrets in argv. Payloads and secrets are never logged.

Anonymous creation is bounded per IP and by global broker limits. TCP accepts,
handshakes, pending streams, UDP flows, datagram size, packet rates, and queues
all have limits. Admin sessions are HttpOnly/SameSite cookies with scrypt
password hashes, login throttling, CSRF checks, and an audit log. CIDR blocks
are enforced before creation. Parameterized SQLite queries, escaped templates,
security headers, request-size limits, and passive-only `llms` validation cover
the control plane.

See [threat-model.md](threat-model.md) and rotate all credentials if a secret is
accidentally printed or copied to an insecure location.
