# Protocol

The normative protocol is [protocol/protocol.md](../protocol/protocol.md).
TCP control/data connections use TLS 1.2 or 1.3 (1.3 preferred); UDP sessions
use DTLS 1.2 because current OpenSSL has no DTLS 1.3 implementation. Control
frames are bounded, 10-byte-header `TunnelMate/1` messages. Relayed TCP bytes
are unframed after binding. Each UDP application datagram maps to exactly one
DTLS application record containing one 11-byte routing envelope.
