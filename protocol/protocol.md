# TunnelMate Wire Protocol — Version 1

## Protocol identifier and versioning

- Protocol string: `TunnelMate/1`
- Both peers send `HELLO` first; the version field in `HELLO` is `1`.
- If a peer receives a version it cannot handle, it replies `ERROR`
  (`code=PROTOCOL_VERSION`) and closes.
- All framing is independent of transport (TCP/TLS or DTLS datagrams).

## Byte order and integer encoding

All multi-byte integers crossing the wire are **big-endian** (network byte
order). There is no padding in headers; every field is tightly packed.

## Message header (control plane, TCP)

Every control message starts with a fixed 10-byte header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  version=1    |   msg_type    |         payload_length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        payload_length (cont)  |         stream_id (32)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `version` — 1 byte, must be 1.
- `msg_type` — 1 byte, see table below.
- `payload_length` — 4 bytes big-endian, max `MAX_FRAME_PAYLOAD` (256 KiB).
- `stream_id` — 4 bytes big-endian, present in every control message. Used by
  messages that refer to a stream; 0 when unused.

**Strict length validation**: a receiver must reject a frame whose declared
length exceeds the maximum *before* allocating any buffer. Malformed frames
cause: reject, log bounded diagnostic (hex prefix, first 64 bytes max),
close connection, increment `protocol_errors` metric.

## Control message types

| Value | Name | Payload | Direction |
|-------|------|---------|-----------|
| 1 | `HELLO` | proto string `TunnelMate/1` | agent→broker, broker→agent |
| 2 | `HELLO_ACK` | none | both |
| 3 | `REGISTER` | tunnel id + agent secret (see below) | agent→broker |
| 4 | `REGISTER_OK` | none | broker→agent |
| 5 | `REGISTER_ERROR` | error string (≤256 B) | broker→agent |
| 6 | `PING` | none | both |
| 7 | `PONG` | none | both |
| 8 | `OPEN_STREAM` | none (stream_id used) | broker→agent |
| 9 | `OPEN_STREAM_ACK` | none | agent→broker |
| 10 | `OPEN_STREAM_ERROR` | error string (≤256 B) | agent→broker |
| 11 | `DATA_BIND` | none (stream_id used) | agent→broker |
| 12 | `DATA_BIND_OK` | none | broker→agent |
| 13 | `DATA_BIND_ERROR` | error string (≤256 B) | broker→agent |
| 14 | `CLOSE_STREAM` | none (stream_id used) | both |
| 15 | `GOING_AWAY` | reason string (≤256 B) | broker→agent |
| 16 | `ERROR` | error string (≤256 B) | both |
| 17 | `KILL_STREAM` | none (stream_id used) | broker→agent |
| 18 | `REGISTER_ACK` (reserved) | — | — |
| 19 | `AUTH` | token_id + token (closed peers) | peer→broker |
| 20 | `AUTH_OK` | none | broker→peer |
| 21 | `AUTH_ERROR` | error string (≤256 B) | broker→peer |

`REGISTER` payload layout:

```text
+------------------+----------------------+---------------------------+
| tunnel_id_len(2) | tunnel_id (bytes)    | agent_secret (remaining)  |
+------------------+----------------------+---------------------------+
```

Both fields are UTF-8 strings. `tunnel_id` max 128 bytes, `agent_secret` max
256 bytes, total frame ≤ max payload.

Error strings are UTF-8, ≤ 256 bytes, and are logged only at debug level.

## TCP data connection protocol

A data connection is a fresh TLS connection (agent→broker, or
peer→broker for closed tunnels). It begins with a binary handshake before any
payload flows:

```text
agent -> broker: DATA_BIND frame (header with stream_id, no payload)
broker -> agent: DATA_BIND_OK / DATA_BIND_ERROR
```

For closed tunnels the data connection carries an authentication preamble:

```text
closed peer -> broker: AUTH frame
   AUTH payload: token_id_len(2) + token_id + token(remaining)
broker -> peer: AUTH_OK / AUTH_ERROR   (then peer sends DATA_BIND)
```

`AUTH_OK`/`AUTH_ERROR` are message types 19/20 (see table).

After `DATA_BIND_OK` both sides relay **raw stream bytes** with no additional
framing. EOF is signaled by TLS close-notify; half-close is honored via
`SSL_shutdown` semantics. `CLOSE_STREAM` on the control channel forces the
stream closed.

## UDP (DTLS) datagram envelope

The UDP data path uses DTLS 1.2 records (OpenSSL) directly as the transport.
Inside each DTLS application-data record, TunnelMate places a compact
envelope so the receiver can route the datagram:

```text
+------------------+------------------+------------------+-------------+
| envelope_len (2) | flow_id (8 B)    | flags (1 B)      | payload     |
+------------------+------------------+------------------+-------------+
```

- `envelope_len` — big-endian 16-bit, length of envelope header itself (11).
- `flow_id` — 64-bit big-endian flow identifier assigned by the broker.
- `flags` — bit 0: direction (0 = peer→service, 1 = service→peer). Reserved
  bits must be 0; set bits cause the datagram to be dropped and counted.
- `payload` — the original UDP payload, verbatim. Datagram boundaries are
  preserved: one DTLS record in → one envelope out → one raw UDP datagram out.
- Maximum payload is `udp_max_datagram_size` (default 1400). Oversized
  datagrams are dropped and counted (`udp_dropped_oversize`); they are never
  truncated.

Flow routing on the broker:

```text
raw UDP from Internet (dst=public_udp_port)
   -> lookup/create flow (tunnel, src_ip, src_port)
   -> flow_id assigned, send envelope over DTLS to agent
agent -> local UDP socket per flow -> service
service reply on same socket -> envelope with flow_id -> broker
broker -> raw UDP to original (src_ip, src_port)
```

## Heartbeat

- `PING` is sent every `heartbeat_interval` (default 30 s, agent and broker).
- A peer that has not received any traffic (`PING`, `PONG`, or data) for
  `heartbeat_timeout = interval * missed_count` (default 90 s) declares the
  connection dead and closes it.
- Reconnect timers add ±20% jitter to avoid synchronized reconnect storms.

## Limits (protocol level)

| Limit | Default | Enforced |
|---|---|---|
| max frame payload | 256 KiB | reject before allocation |
| max control message size | 256 KiB + 10 | reject before allocation |
| max tunnel id | 128 B | reject |
| max secret/token | 256 B | reject |
| max error string | 256 B | truncate, log at debug |
| max udp datagram payload | 1400 B | drop + metric |

## Compatibility

The framing deliberately separates control messages (reliable TCP/TLS) from
stream bytes (unframed relay) and datagrams (DTLS envelopes). Future
multiplexing or pre-established worker connections can be introduced by adding
message types without breaking `TunnelMate/1` framing.
