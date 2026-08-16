# ADR-0001: TCP Data Plane — TLS Control + Per-Stream TLS Data Connections

Status: Accepted

## Context

The agent must traverse NAT/CGNAT by making outbound connections to the
broker. TCP payloads must be encrypted. The protocol must tolerate future
multiplexing without breaking v1.

## Decision

- One long-lived **TLS control connection** (agent→broker) carries
  `REGISTER`, heartbeats, and `OPEN_STREAM` notifications.
- For each public connection, the agent opens a **fresh TLS data connection**
  and binds it to the stream id (`DATA_BIND`). The broker then relays raw
  bytes between the public socket and that encrypted socket with **no
  per-chunk framing**.
- This gives us: TCP semantics preserved (half-close, FIN/RST), no
  head-of-line issues beyond ordinary TCP, simple backpressure via libuv
  read/write watermarks, and per-stream TLS connections that are trivially
  replaceable by a multiplexed channel later.

## Consequences

- Connection establishment cost per stream (a TLS handshake). Acceptable for
  v1; measured in the performance docs.
- The control connection is the failure domain for tunnel *lifecycle*; stream
  data survives control-plane churn per-stream only while its data connection
  lives.

## Alternatives rejected

- Single multiplexed TLS channel with framed chunks: more complex framing and
  buffering, worse backpressure isolation, no half-close per stream.
- UDP-over-TCP encapsulation for TCP: violates TCP semantics requirement.