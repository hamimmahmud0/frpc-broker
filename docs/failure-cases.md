# Failure cases

Every row records what breaks, what TunnelMate does about it, what the operator
and the user see, and the test that holds the behaviour in place. Where a fault
kills traffic, that is stated plainly rather than dressed up as recovery: an
interrupted TCP stream cannot be resumed, and TunnelMate does not pretend
otherwise.

Test names below are pytest node ids unless marked `[manual]` or `[root]`.
Run them with `TUNNELMATE_BUILD_DIR=$PWD/build .venv/bin/pytest <path>`.

Log fields are the structured keys described in [operations.md](operations.md).
No row logs payload bytes or credentials, in any branch, at any level.

---

## 1. Control plane and process lifecycle

### Broker unavailable (never started, or crashed)

| | |
|---|---|
| **Expected** | The API stays up and serves reads. Tunnel creation fails closed with `503 BROKER_UNAVAILABLE`; readiness reports not-ready. Existing relays do not exist, because the broker is the relay. |
| **User-visible** | `POST /v1/tunnels` → 503. `GET /health/ready` → 503. `GET /health/live` → 200, because the API process itself is healthy. |
| **Logs** | `event=ipc_unavailable` from the API. No stack trace reaches the response body. |
| **Recovery** | Automatic once the broker returns: the API restores every unexpired tunnel from SQLite on its next `restore_runtime` pass. |
| **Test** | `tests/failure/test_failure.py::test_broker_ipc_unavailable_is_a_clean_error` |

### Broker restart

| | |
|---|---|
| **Expected** | Active streams die with the process — TCP cannot survive it. The control plane recreates runtime tunnels; each agent reconnects on its own backoff and starts accepting new connections. |
| **User-visible** | In-flight transfers abort. New connections succeed within a few seconds (measured ~2 s on loopback). |
| **Logs** | `event=shutdown_start`, `shutdown_complete`, then `broker_started` and one `agent_registered` per returning agent. |
| **Recovery** | Automatic. The agent treats `GOING_AWAY` as "retire this connection", not "exit". |
| **Test** | `tests/failure/test_failure.py::test_broker_restart_agent_reconnects_with_backoff` |

### FastAPI unavailable or restarted

| | |
|---|---|
| **Expected** | Nothing happens to traffic. The planes are separate processes and Python is never in the payload path. |
| **User-visible** | Active relays keep flowing at full rate. Tunnel creation and the console are unavailable until the API returns. |
| **Logs** | Nothing from the broker; systemd records the API restart. |
| **Recovery** | Automatic; on start the API reconciles SQLite against the broker's live registry. |
| **Test** | `tests/failure/test_failure.py::test_broker_ipc_unavailable_is_a_clean_error` (inverse direction), plus the isolation check in `docs/testing.md` |

### SIGTERM

| | |
|---|---|
| **Expected** | Stop accepting new tunnels and streams, send `GOING_AWAY` to connected agents, allow active streams the configured grace period (`shutdown_grace_ms`), then close and exit 0. |
| **User-visible** | Transfers finishing inside the grace window complete. Longer ones are cut at the deadline. |
| **Logs** | `event=shutdown_start reason=graceful`, then `shutdown_complete`. |
| **Recovery** | Agents reconnect when the broker returns. |
| **Test** | `tests/failure/test_failure.py::test_sigterm_is_graceful_and_sigkill_is_survivable` |

### SIGKILL

| | |
|---|---|
| **Expected** | Immediate death. No grace, no `GOING_AWAY`, no flush. This is not recoverable in-process and is not treated as a supported shutdown. |
| **User-visible** | Every stream resets at once. |
| **Logs** | Nothing from the broker; systemd records the signal. |
| **Recovery** | systemd restarts the unit; agents reconnect; the API restores the registry. |
| **Test** | `tests/failure/test_failure.py::test_sigterm_is_graceful_and_sigkill_is_survivable` |

### Broker IPC socket unavailable or path too long

| | |
|---|---|
| **Expected** | A broker that cannot bind its IPC socket exits non-zero at startup rather than running unmanageably. An over-long `broker_socket` is rejected explicitly instead of being silently truncated by `sun_path`. |
| **User-visible** | The service fails to start; `systemctl status` shows the exit. |
| **Logs** | `event=ipc_path_too_long` or `ipc_bind_failed` with the libuv reason. |
| **Recovery** | Operator action: shorten the path or fix permissions. |
| **Test** | `tests/failure/test_failure.py::test_broker_ipc_unavailable_is_a_clean_error` |

### SQLite unavailable, corrupt, or disk full

| | |
|---|---|
| **Expected** | Readiness fails and mutating API calls return 503. The broker is untouched and keeps relaying, because it holds its registry in memory. |
| **User-visible** | Existing tunnels keep working; new ones cannot be created. |
| **Logs** | API logs the sqlite error class, never the statement parameters. |
| **Recovery** | Operator action: free space or restore the database. See [troubleshooting.md](troubleshooting.md). |
| **Test** | `control/tests/test_api.py::test_validation_and_health` |

### Disk nearly full

| | |
|---|---|
| **Expected** | Payload never touches disk, so transfers are unaffected. Only SQLite writes and journald are at risk. |
| **User-visible** | Tunnels keep relaying; announcements may fail to persist. |
| **Logs** | journald begins dropping per its `SystemMaxUse` cap. |
| **Recovery** | Operator action. The console's disk tile is the early warning. |
| **Test** | `tests/security/test_admin_ui.py::test_host_readings_are_sane` (surfacing), `[manual]` for the full-disk condition |

---

## 2. Agent and registration

### Agent network disconnect

| | |
|---|---|
| **Expected** | The broker marks the tunnel offline within the heartbeat timeout and closes every orphaned stream. The agent detects the drop and reconnects with exponential backoff plus jitter. |
| **User-visible** | Active connections drop. New connections to the public port are accepted and immediately closed while offline. |
| **Logs** | `event=agent_dropped reason=eof|timeout`, then `agent_registered` on return. `conns_rejected_offline` increments per refused connection. |
| **Recovery** | Automatic for new connections. Interrupted streams are gone. |
| **Test** | `tests/failure/test_failure.py::test_agent_disconnect_then_reconnect_resumes_new_streams` |

### Heartbeat timeout

| | |
|---|---|
| **Expected** | A peer that has seen no traffic for `heartbeat_interval × missed_count` declares the connection dead and closes it, rather than holding a half-open socket. |
| **User-visible** | Same as a disconnect. |
| **Logs** | `event=control_idle_timeout`. |
| **Recovery** | Automatic reconnect. |
| **Test** | `tests/failure/test_failure.py::test_agent_disconnect_then_reconnect_resumes_new_streams` |

### Agent reconnect storm

| | |
|---|---|
| **Expected** | Reconnect delays carry ±20% jitter so a fleet does not resynchronise. The broker absorbs the burst without wedging. |
| **User-visible** | Tunnels return over a spread of a few seconds rather than all at once. |
| **Logs** | A run of `agent_registered` events; `agent_reconnects` climbs. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_agent_reconnect_storm_is_absorbed` |

### Wrong agent secret, or registration for a tunnel that does not exist

| | |
|---|---|
| **Expected** | Both are refused with the same `REGISTER_ERROR` payload after the same HMAC work, so registration cannot be used to enumerate tunnel ids. `failed_auths` increments. |
| **User-visible** | The agent logs a rejection and retries on backoff; it never reaches a service. |
| **Logs** | `event=register_rejected`. The offered secret is never logged. |
| **Recovery** | Operator action: issue a fresh config with a valid secret. |
| **Test** | `tests/security/test_data_plane_security.py::test_registration_for_unknown_tunnel_looks_the_same_as_a_bad_secret` |

### Expired, disabled, or deleted tunnel

| | |
|---|---|
| **Expected** | Disabling closes the listener. Deleting closes the listener, drops the agent, terminates active streams, releases the public port and disables announcements. The lease reaper deletes expired tunnels on its next pass. |
| **User-visible** | Connection refused on the public port. Announcements stop appearing as online. |
| **Logs** | `event=tunnel_deleted`, plus an audit row when an administrator did it. |
| **Recovery** | None by design — deletion is intentional. Re-enable is available for disable. |
| **Test** | `tests/failure/test_failure.py::test_disabled_and_deleted_tunnel_stop_serving`, `tests/security/test_control_plane_security.py::test_expired_tunnels_are_reaped_and_release_their_port` |

---

## 3. TCP data path

### Local service unavailable

| | |
|---|---|
| **Expected** | The stream that needed it fails. The tunnel stays online and other streams are unaffected. |
| **User-visible** | The client sees a connection that opens and then closes with no data. |
| **Logs** | `event=stream_closed` with byte counts of zero. |
| **Recovery** | Automatic once the local service returns; no agent restart needed. |
| **Test** | `tests/failure/test_failure.py::test_local_service_unavailable_closes_only_that_stream` |

### Local service closes early

| | |
|---|---|
| **Expected** | The half-close propagates. Bytes already queued toward the client are flushed before the FIN. |
| **User-visible** | A clean EOF, not a reset, and no truncated tail. |
| **Logs** | `event=relay_b_eof` at debug. |
| **Recovery** | Not applicable; this is normal protocol behaviour. |
| **Test** | `tests/failure/test_failure.py::test_local_service_closes_early` |

### Client half-close, server half-close

| | |
|---|---|
| **Expected** | Shutdown in one direction leaves the other direction usable. The FIN is only emitted once the queued tail for that direction has drained. |
| **User-visible** | Request/response protocols that half-close (the classic `shutdown(SHUT_WR)` then read) work correctly. |
| **Logs** | Debug only. |
| **Recovery** | Not applicable. |
| **Test** | `tests/integration/test_data_plane.py::test_tcp_half_close_drains_queued_tail` |

### Client RST / abortive close

| | |
|---|---|
| **Expected** | The dead leg is closed and its buffers freed; the surviving leg is torn down rather than writing into a closed peer. No descriptor leak. |
| **User-visible** | Nothing beyond the aborted connection. |
| **Logs** | `event=relay_a_error` at warning with the transport reason. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_client_reset_frees_broker_resources` |

### Peer disappears mid-write (SIGPIPE)

| | |
|---|---|
| **Expected** | The write fails with `EPIPE` and closes one stream. Every binary ignores `SIGPIPE`, so a rude client cannot terminate the broker and take every other tunnel with it. |
| **User-visible** | Only the aborting connection is affected. |
| **Logs** | `event=relay_a_error err=-4`. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_broker_survives_sigpipe_from_a_vanishing_reader` |

### Slow consumer / slow producer

| | |
|---|---|
| **Expected** | Backpressure, not buffering. Reads pause at the 256 KiB high watermark and resume below 128 KiB. Queued bytes are bounded and a stalled reader stalls the producer instead of growing the broker. |
| **User-visible** | Throughput matches the slowest hop. Nothing is dropped on TCP. |
| **Logs** | Debug only. |
| **Recovery** | Automatic when the consumer drains. |
| **Test** | `tests/load/test_concurrency.py::test_slow_consumer_does_not_grow_broker_memory` (measured: 72 KiB growth over a 6 s stall) |

### 5+ GiB stream

| | |
|---|---|
| **Expected** | Unlimited stream length with bounded memory and no disk spooling. Byte-exact delivery in both open and closed mode. |
| **User-visible** | Large uploads and downloads complete with a matching hash. |
| **Logs** | One `stream_closed` line with the byte totals. |
| **Recovery** | Not applicable. |
| **Test** | `tests/integration/test_data_plane.py::test_large_open_tcp_stream_without_spooling` and `::test_large_closed_tcp_stream_without_spooling` (measured on the target VPS: 6 GiB, matching SHA-256, broker peak RSS ~10 MB) |

### Connection flood / port exhaustion / descriptor limit

| | |
|---|---|
| **Expected** | Per-source-IP connect rate limiting, a global stream cap, a per-tunnel cap and a pending-stream cap. A full public port range returns a deterministic create error rather than binding anything else. |
| **User-visible** | Excess connections are closed immediately; creation returns an error. |
| **Logs** | `conns_rate_limited` increments; `event=bind_public_failed` on exhaustion. |
| **Recovery** | Automatic as load subsides. |
| **Test** | `tests/security/test_data_plane_security.py::test_connection_flood_is_bounded`, `tests/failure/test_failure.py::test_port_exhaustion_fails_deterministically` |

---

## 4. UDP data path

UDP is not TCP with different framing, and these rows do not treat it as such.
There is no connection to break, no retransmission, and loss under load is
legitimate rather than a fault. What must hold is that datagram boundaries
survive, replies reach the right sender, and queues stay bounded.

### Local UDP service unavailable

| | |
|---|---|
| **Expected** | Datagrams are forwarded and simply go unanswered. There is no connection to fail and no error to report. |
| **User-visible** | No reply. The tunnel stays online. |
| **Logs** | None per datagram — per-packet logging is forbidden. |
| **Recovery** | Automatic once the service returns. |
| **Test** | `tests/failure/test_failure.py::test_udp_local_service_unavailable_does_not_kill_the_tunnel` |

### Oversized datagram

| | |
|---|---|
| **Expected** | Dropped whole and counted. Never truncated, because a shortened datagram would silently corrupt the application's message. The boundary is exact: `udp_max_datagram_size` passes, one byte more does not. |
| **User-visible** | The datagram does not arrive. Senders must respect the documented maximum payload. |
| **Logs** | `udp_dropped_oversize` increments. |
| **Recovery** | Sender must reduce the datagram size. |
| **Test** | `tests/failure/test_failure.py::test_udp_oversized_datagram_is_dropped_not_truncated`, `tests/load/test_udp_load.py::test_udp_oversize_boundary_is_exact` |

### Zero-length datagram

| | |
|---|---|
| **Expected** | Delivered as a zero-length datagram. It is legal UDP and some protocols use it as a signal, so it must not be confused with "no data available". |
| **User-visible** | The empty datagram arrives intact. |
| **Logs** | None. |
| **Recovery** | Not applicable. |
| **Test** | `tests/failure/test_failure.py::test_udp_zero_length_datagram_round_trips` |

### Flow idle timeout

| | |
|---|---|
| **Expected** | Mappings expire after `udp_flow_idle_timeout_ms` so the broker never accumulates state for every historical sender. A later datagram from the same address simply creates a new flow. |
| **User-visible** | A long-idle client transparently gets a fresh flow. Applications that need longer mappings raise the timeout. |
| **Logs** | `udp_flow_expired` increments. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_udp_flow_idle_timeout_reclaims_state` |

### Many source addresses and ports / flow table exhaustion

| | |
|---|---|
| **Expected** | Each source tuple is an independent flow with independent reply routing. Beyond `udp_max_flows_per_tunnel` (or the global cap) new flows are refused, not evicted at random. |
| **User-visible** | Established clients keep working; new ones are dropped while the table is full. |
| **Logs** | `udp_dropped_no_flow` and `udp_dropped_rate_limit` increment. |
| **Recovery** | Automatic as idle flows expire. |
| **Test** | `tests/load/test_concurrency.py::test_many_udp_flows_are_routed_independently` (measured: 128 concurrent flows, zero misrouted, zero lost) |

### Reply routing with multiple simultaneous clients

| | |
|---|---|
| **Expected** | Replies return to the originating address only. Two clients using one tunnel never see each other's traffic. The agent keeps a NAT-style mapping with one local socket per active flow, so the local service sees ordinary UDP with no injected metadata. |
| **User-visible** | Correct request/reply pairing under concurrency. |
| **Logs** | None per datagram. |
| **Recovery** | Not applicable. |
| **Test** | `tests/failure/test_failure.py::test_udp_many_sources_keep_independent_flows`, `tests/load/test_concurrency.py::test_dns_like_request_reply_from_many_clients` |

### Datagram flood

| | |
|---|---|
| **Expected** | Per-tunnel and per-source packet rate limits, a bounded queue per session, and a bounded number of outstanding sends toward each client. Excess is dropped by policy and counted; memory does not grow. |
| **User-visible** | Loss during the flood. The tunnel keeps serving traffic within the limits. |
| **Logs** | `udp_dropped_rate_limit`, `udp_dropped_queue_full`. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_udp_flood_is_rate_limited_without_unbounded_memory` |

### Sustained UDP volume above 5 GB

| | |
|---|---|
| **Expected** | Aggregate volume is unlimited with bounded memory. This is total transferred bytes, not one enormous datagram. |
| **User-visible** | Continuous telemetry or media streams keeps running indefinitely. |
| **Logs** | Counters only. |
| **Recovery** | Not applicable. |
| **Test** | `tests/load/test_udp_load.py::test_udp_aggregate_volume_exceeds_five_gigabytes` (measured: 6 GiB aggregate, broker peak RSS 11.5 MB — about 2 MB over idle) |

### Packet loss, duplication, reordering

| | |
|---|---|
| **Expected** | TunnelMate neither retransmits nor reorders. Loss under stress is passed through as loss. Duplication is never introduced by the tunnel. On an unloaded loopback or namespace path, loss is effectively zero. |
| **User-visible** | UDP semantics, unchanged. Applications keep their own reliability if they need it. |
| **Logs** | Drop counters distinguish the reason. |
| **Recovery** | Application's responsibility, by design. |
| **Test** | `tests/load/test_udp_load.py::test_udp_realtime_stream_jitter_and_order` (measured: 2000 datagrams, 0 lost, 0 duplicated, 0 reordered) |

### Agent disconnect during a UDP flow, and agent reconnect

| | |
|---|---|
| **Expected** | Flow state dies with the DTLS session. A restarted agent re-authenticates and serves new flows; old flow ids are not resurrected. |
| **User-visible** | In-flight datagrams are lost; new ones work once the agent is back. |
| **Logs** | `event=udp_session_closed`, then a new `udp_session_new`. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_udp_agent_restart_recovers_flows` |

### NAT rebinding

| | |
|---|---|
| **Expected** | For open UDP tunnels a changed source tuple is a new flow — the broker will not assume two source addresses are the same client, because that would let one client hijack another's flow. Closed peers carry an authenticated session identity instead. |
| **User-visible** | A mobile client that changes network gets a fresh flow. Long-lived sessions should use closed mode. |
| **Logs** | `udp_flow_created` increments. |
| **Recovery** | Automatic, as a new flow. |
| **Test** | `tests/failure/test_failure.py::test_udp_many_sources_keep_independent_flows` |

---

## 5. DTLS datagram transport

The UDP tunnel is carried over DTLS 1.2 (see
[ADR-0002](adr/0002-udp-transport.md)); these are its transport-level faults,
kept separate from application UDP behaviour above.

### DTLS handshake failure or certificate rejection

| | |
|---|---|
| **Expected** | No session is established and no datagram is relayed. Verification is on by default; disabling it must be explicit configuration. |
| **User-visible** | The UDP tunnel never comes online. |
| **Logs** | `event=udp_session_closed` with the OpenSSL reason, bounded and free of user data. |
| **Recovery** | Operator action: install the correct CA or fix the certificate SAN. |
| **Test** | `tests/security/test_data_plane_security.py::test_agent_rejects_untrusted_certificate_by_default` (TCP equivalent; DTLS shares the verification path) |

### DTLS session loss and re-establishment

| | |
|---|---|
| **Expected** | The agent re-handshakes and re-authenticates. Flows established under the old session are not carried across. |
| **User-visible** | A gap in datagram delivery during re-establishment. |
| **Logs** | `udp_transport_errors` increments on transport failure. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_udp_agent_restart_recovers_flows` |

### Effective MTU and fragmentation

| | |
|---|---|
| **Expected** | The DTLS link MTU is pinned at 1400 bytes and application datagrams are capped below it, so TunnelMate does not create IP fragmentation and does not invent its own fragmentation scheme. Datagrams past the limit are dropped, not split. |
| **User-visible** | Applications must keep payloads at or below the configured maximum (1400 by default). |
| **Logs** | `udp_dropped_oversize`. |
| **Recovery** | Sender-side: reduce the datagram size. |
| **Test** | `tests/load/test_udp_load.py::test_udp_datagram_sizes_survive_round_trip` |

### Closed UDP peer presents a wrong token

| | |
|---|---|
| **Expected** | Authentication happens inside DTLS with a constant-time comparison. A wrong token relays nothing, and the reply is identical whether or not the tunnel exists. |
| **User-visible** | No traffic reaches the service; the peer sees no distinguishing error. |
| **Logs** | `failed_auths` increments. |
| **Recovery** | Operator action: use the correct shared token. |
| **Test** | `tests/failure/test_failure.py::test_closed_udp_wrong_token_is_rejected` |

---

## 6. Protocol and untrusted input

### Malformed protocol message

| | |
|---|---|
| **Expected** | Reject, log a bounded diagnostic, close the connection, increment `protocol_errors`. The process survives every case. Attacker-controlled bytes are never dumped into the log. |
| **User-visible** | The offending connection closes. Nothing else is affected. |
| **Logs** | `event=protocol_error` with a bounded prefix only. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_malformed_control_frames_never_crash_the_broker` |

### Oversized frame

| | |
|---|---|
| **Expected** | A declared length above `MAX_FRAME_PAYLOAD` is refused **before** any allocation, so a 4 GiB claim costs nothing. |
| **User-visible** | Connection closed. |
| **Logs** | `protocol_errors` increments. |
| **Recovery** | Automatic. |
| **Test** | `tests/security/test_data_plane_security.py::test_oversized_frame_is_rejected_before_allocation` |

### Plaintext connection to a TLS port

| | |
|---|---|
| **Expected** | The handshake fails and the connection closes. There is no plaintext fallback and no downgrade. |
| **User-visible** | Connection closed with no data. |
| **Logs** | Debug only. |
| **Recovery** | Client must use TLS. |
| **Test** | `tests/security/test_data_plane_security.py::test_control_port_requires_tls` |

### Slowloris / stalled handshake

| | |
|---|---|
| **Expected** | Connections that never complete a handshake are dropped at `handshake_timeout_ms`, so they cannot accumulate. |
| **User-visible** | Nothing. |
| **Logs** | `event=handshake_timeout`. |
| **Recovery** | Automatic. |
| **Test** | `tests/security/test_data_plane_security.py::test_slowloris_handshake_is_timed_out` |

### Malformed IPC input

| | |
|---|---|
| **Expected** | The IPC socket is trusted but still validated: bad JSON, unknown ops, missing fields and over-long ids are refused without affecting the broker. |
| **User-visible** | The API surfaces a 503 or a validation error. |
| **Logs** | Bounded error only. |
| **Recovery** | Automatic. |
| **Test** | `tests/failure/test_failure.py::test_malformed_ipc_input_is_rejected` |

---

## 7. Control API and registry

### Announcement with an invalid `llms` URL

| | |
|---|---|
| **Expected** | Rejected with 422. Only `http(s)` URLs of bounded length are accepted, and the server never fetches them, so there is no SSRF oracle. |
| **User-visible** | `422 VALIDATION_ERROR` with the offending field named and no echo of unbounded input. |
| **Logs** | Request id only. |
| **Recovery** | Caller fixes the URL. |
| **Test** | `tests/security/test_control_plane_security.py::test_llms_url_must_be_structurally_valid_http`, `::test_llms_url_is_never_fetched` |

### Duplicate announcement

| | |
|---|---|
| **Expected** | Announcements carry their own stable id, so a tunnel may hold more than one. Ownership is enforced by the tunnel's management capability. |
| **User-visible** | Both listings appear; neither can be edited by a stranger. |
| **Logs** | Audit row on admin edits. |
| **Recovery** | Not applicable. |
| **Test** | `tests/security/test_control_plane_security.py::test_announcement_ownership_is_enforced` |

### Modification without the management capability

| | |
|---|---|
| **Expected** | 404, identical to a tunnel that does not exist, so the API is not an existence oracle. |
| **User-visible** | `404 TUNNEL_NOT_FOUND`. |
| **Logs** | Request id only; the offered secret is never logged. |
| **Recovery** | Caller supplies the right capability. |
| **Test** | `tests/security/test_control_plane_security.py::test_management_secret_is_scoped_to_one_tunnel`, `::test_missing_or_wrong_secret_is_indistinguishable` |

### Admin brute force

| | |
|---|---|
| **Expected** | Login is rate limited per source and passwords are stored as salted scrypt digests. No default administrator ships. |
| **User-visible** | `429` after a short burst of failures. |
| **Logs** | Audit rows for login attempts; never the password. |
| **Recovery** | Automatic as the window slides. |
| **Test** | `tests/security/test_control_plane_security.py::test_admin_login_is_rate_limited`, `::test_no_default_admin_exists` |

### Oversized API body

| | |
|---|---|
| **Expected** | Refused at the middleware on `Content-Length`, before the body is read. |
| **User-visible** | `413 REQUEST_TOO_LARGE`. |
| **Logs** | Request id only. |
| **Recovery** | Caller sends less. |
| **Test** | `tests/security/test_control_plane_security.py::test_oversized_request_body_is_refused` |

---

## 8. TLS and DNS

### Invalid or expired certificate

| | |
|---|---|
| **Expected** | A verifying client refuses to connect. TunnelMate never silently disables validation; `verify_ca=false` must be set explicitly and is documented as development-only. |
| **User-visible** | The agent or peer never registers and logs a certificate error. |
| **Logs** | `event=control_tls_error` with the OpenSSL reason. |
| **Recovery** | Operator action: renew or install the correct certificate. |
| **Test** | `tests/security/test_data_plane_security.py::test_agent_rejects_untrusted_certificate_by_default` |

### TLS downgrade attempt

| | |
|---|---|
| **Expected** | Minimum TLS 1.2 with 1.3 preferred; DTLS 1.2 for datagrams. TLS 1.0/1.1 handshakes fail. |
| **User-visible** | Connection refused. |
| **Logs** | Debug only. |
| **Recovery** | Not applicable. |
| **Test** | `tests/security/test_data_plane_security.py::test_obsolete_tls_versions_are_refused` |

### DNS failure

| | |
|---|---|
| **Expected** | The agent cannot resolve the broker, logs a bounded error, and retries on the same backoff as any other connect failure. |
| **User-visible** | The tunnel stays offline until DNS recovers. |
| **Logs** | `event=connect_failed`. |
| **Recovery** | Automatic. |
| **Test** | `[manual]` — covered operationally; the reconnect path itself is under `test_broker_restart_agent_reconnects_with_backoff` |

---

## 9. NAT traversal

### Internet peer cannot reach the private host directly

| | |
|---|---|
| **Expected** | With the agent behind NAT, the only inbound path is the tunnel the agent dialled out. Direct TCP is refused and direct UDP is unanswered. |
| **User-visible** | The service is reachable through the broker's public port and nowhere else. |
| **Logs** | Normal accept/relay events. |
| **Recovery** | Not applicable. |
| **Test** | `[root]` `tests/nat/nat_scenario.sh` — three network namespaces with MASQUERADE and an explicit inbound DROP; asserts direct access fails and both TCP and UDP work through the tunnel with datagram sizes preserved |

---

## Coverage note

`journalctl` output contains metadata and error codes only — never credentials,
never payload bytes, in any branch. The automatic-recovery column never claims
that an interrupted TCP stream resumes; recovery means new connections succeed
again.
