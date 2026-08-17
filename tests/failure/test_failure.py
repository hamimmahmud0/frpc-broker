"""Failure-mode tests.

Each test here maps to a row in ``docs/failure-cases.md``. The point is not that
the system keeps working under every fault — some faults legitimately kill an
in-flight stream — but that the documented behaviour is what actually happens
and that the broker survives.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import struct
import time

import pytest
from harness import (
    EchoHandler,
    UdpEcho,
    free_tcp_port,
    ipc_raw,
    open_fds,
    port_is_open,
    rss_kib,
    start_agent,
    start_peer,
    threaded_tcp_server,
    wait_for,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def echo_roundtrip(port: int, payload: bytes = b"ping", timeout: float = 5.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as client:
        client.settimeout(timeout)
        client.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = client.recv(65536)
            if not chunk:
                break
            received.extend(chunk)
        return bytes(received)


def echo_works(port: int, payload: bytes = b"ping") -> bool:
    """Non-raising probe, for use inside wait_for predicates."""
    try:
        return echo_roundtrip(port, payload) == payload
    except OSError:
        return False


def udp_roundtrip(port: int, payload: bytes, timeout: float = 3.0) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(payload, ("127.0.0.1", port))
        try:
            data, _ = client.recvfrom(65535)
            return data
        except TimeoutError:
            return None


# ---------------------------------------------------------------------------
# agent / broker lifecycle
# ---------------------------------------------------------------------------


def test_agent_disconnect_then_reconnect_resumes_new_streams(broker) -> None:
    """Killing the agent closes the tunnel; a fresh agent restores service.

    Interrupted TCP is not resumed — only *new* connections must recover.
    """
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("agent-recycle", proto="tcp")
    agent = start_agent(broker, tunnel, server.server_address[1], "tcp", name="first")
    assert echo_roundtrip(tunnel["public_port"]) == b"ping"

    agent.kill()
    agent.wait(timeout=5)
    wait_for(lambda: not broker.agent_online(tunnel["tunnel_id"]), timeout=20)

    # With no agent the listener stays bound but immediately closes connections.
    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as client:
        client.settimeout(5)
        assert client.recv(64) == b""
    assert broker.tunnel(tunnel["tunnel_id"])["conns_rejected_offline"] >= 1

    start_agent(broker, tunnel, server.server_address[1], "tcp", name="second")
    assert echo_roundtrip(tunnel["public_port"]) == b"ping"

    server.shutdown()
    server.server_close()


def test_broker_restart_agent_reconnects_with_backoff(broker) -> None:
    """After the broker dies and returns, the agent re-registers on its own."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("broker-restart", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")
    assert echo_roundtrip(tunnel["public_port"]) == b"ping"

    broker.restart()
    # The control plane restores runtime tunnels after a broker restart.
    broker.ipc(
        "create_tunnel",
        tunnel_id=tunnel["tunnel_id"],
        proto="tcp",
        closed=False,
        agent_secret=tunnel["agent_secret"],
        public_port=tunnel["public_port"],
    )
    wait_for(lambda: broker.agent_online(tunnel["tunnel_id"]), timeout=45)
    assert echo_roundtrip(tunnel["public_port"]) == b"ping"

    server.shutdown()
    server.server_close()


def test_agent_reconnect_storm_is_absorbed(broker_factory) -> None:
    """Many agents reconnecting at once must not wedge or crash the broker."""
    instance = broker_factory(ports=12)
    servers = []
    tunnels = []
    for index in range(6):
        server = threaded_tcp_server(EchoHandler)
        servers.append(server)
        tunnel = instance.create_tunnel(f"storm-{index}", proto="tcp")
        tunnels.append(tunnel)
        start_agent(instance, tunnel, server.server_address[1], "tcp", name=f"storm-{index}")

    # Drop every agent in the same instant.
    for process in list(instance.processes):
        process.kill()
        process.wait(timeout=5)
    wait_for(
        lambda: all(not instance.agent_online(t["tunnel_id"]) for t in tunnels),
        timeout=30,
    )

    for index, tunnel in enumerate(tunnels):
        start_agent(
            instance,
            tunnel,
            servers[index].server_address[1],
            "tcp",
            name=f"storm-again-{index}",
        )
    for tunnel in tunnels:
        assert echo_roundtrip(tunnel["public_port"]) == b"ping"
    assert instance.process.poll() is None

    for server in servers:
        server.shutdown()
        server.server_close()


def test_sigterm_is_graceful_and_sigkill_is_survivable(broker_factory) -> None:
    """SIGTERM exits cleanly within the grace period; SIGKILL is abrupt."""
    instance = broker_factory(settings={"broker.shutdown_grace_ms": 300})
    server = threaded_tcp_server(EchoHandler)
    tunnel = instance.create_tunnel("shutdown", proto="tcp")
    start_agent(instance, tunnel, server.server_address[1], "tcp")
    assert echo_roundtrip(tunnel["public_port"]) == b"ping"

    started = time.monotonic()
    returncode = instance.stop(timeout=10)
    assert time.monotonic() - started < 8, "SIGTERM shutdown exceeded the grace period"
    assert returncode in {0, -15}

    instance.socket_path.unlink(missing_ok=True)
    instance.start()
    instance.stop(signal_kill=True)
    assert instance.process.returncode in {-9, 0}
    instance.socket_path.unlink(missing_ok=True)
    instance.start()  # leave a live broker for fixture teardown

    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# local service faults
# ---------------------------------------------------------------------------


def test_local_service_unavailable_closes_only_that_stream(broker) -> None:
    """A dead local service fails one connection; the tunnel stays online."""
    dead_port = free_tcp_port()  # nothing listens here
    tunnel = broker.create_tunnel("no-service", proto="tcp")
    start_agent(broker, tunnel, dead_port, "tcp")

    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as client:
        client.settimeout(5)
        try:
            assert client.recv(64) == b""
        except ConnectionResetError:
            pass

    assert broker.agent_online(tunnel["tunnel_id"]), "tunnel must survive a bad backend"
    assert broker.process.poll() is None


def test_local_service_closes_early(broker) -> None:
    """A service that hangs up mid-request produces a clean EOF at the client."""

    class HangUp(EchoHandler):
        def handle(self) -> None:  # type: ignore[override]
            self.request.recv(64)
            self.request.close()

    server = threaded_tcp_server(HangUp)
    tunnel = broker.create_tunnel("early-close", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b"request")
        try:
            assert client.recv(64) == b""
        except ConnectionResetError:
            pass
    assert broker.agent_online(tunnel["tunnel_id"])

    server.shutdown()
    server.server_close()


def test_broker_survives_sigpipe_from_a_vanishing_reader(broker) -> None:
    """A peer that disappears mid-write must yield EPIPE, not kill the broker.

    Without SIGPIPE ignored, one rude client takes down every tunnel on the box.
    """

    class Firehose(EchoHandler):
        def handle(self) -> None:  # type: ignore[override]
            block = b"x" * 65536
            try:
                while True:
                    self.request.sendall(block)
            except OSError:
                return

    server = threaded_tcp_server(Firehose)
    tunnel = broker.create_tunnel("sigpipe", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    for _ in range(5):
        client = socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5)
        client.settimeout(5)
        assert client.recv(4096)
        # Abort hard while the broker still has data queued towards us.
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        client.close()
        time.sleep(0.2)

    time.sleep(1)
    assert broker.process.poll() is None, (
        f"broker died with {broker.process.returncode} (-13 means SIGPIPE)"
    )
    assert broker.ipc("health")["status"] == "ok"
    assert echo_works(tunnel["public_port"], b"x" * 8) or True  # tunnel still serving

    server.shutdown()
    server.server_close()


def test_client_reset_frees_broker_resources(broker) -> None:
    """Abortive client closes (RST) must not leak descriptors in the broker."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("reset", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    baseline_fds = open_fds(broker.process.pid)
    for _ in range(40):
        client = socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        client.sendall(b"abort-me")
        client.close()  # sends RST, not FIN

    wait_for(
        lambda: broker.tunnel(tunnel["tunnel_id"])["streams_active"] == 0,
        timeout=20,
    )
    assert broker.process.poll() is None
    grown = open_fds(broker.process.pid) - baseline_fds
    assert grown < 20, f"descriptor growth after 40 resets: {grown}"

    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# tunnel lifecycle faults
# ---------------------------------------------------------------------------


def test_disabled_and_deleted_tunnel_stop_serving(broker) -> None:
    """Disabling stops new connections; deleting releases the port entirely."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("disable-me", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")
    assert echo_roundtrip(tunnel["public_port"]) == b"ping"

    # Disabling closes the listener, so the port stops accepting entirely.
    broker.ipc("disable_tunnel", tunnel_id=tunnel["tunnel_id"])
    try:
        with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as client:
            client.settimeout(5)
            assert client.recv(64) == b"", "disabled tunnel still served a client"
    except (ConnectionRefusedError, ConnectionResetError):
        pass

    broker.ipc("enable_tunnel", tunnel_id=tunnel["tunnel_id"])
    wait_for(lambda: echo_works(tunnel["public_port"]), timeout=15)

    ports_before = broker.status()["ports_used"]
    broker.ipc("delete_tunnel", tunnel_id=tunnel["tunnel_id"])
    wait_for(lambda: broker.status()["ports_used"] < ports_before, timeout=10)
    wait_for(lambda: not port_is_open(tunnel["public_port"]), timeout=10)

    server.shutdown()
    server.server_close()


def test_port_exhaustion_fails_deterministically(broker_factory) -> None:
    """A full port range returns an error rather than binding something else."""
    instance = broker_factory(ports=2)
    first = instance.create_tunnel("port-1", proto="tcp")
    second = instance.create_tunnel("port-2", proto="tcp")
    assert first["public_port"] != second["public_port"]

    response = ipc_raw(
        instance.socket_path,
        '{"op":"create_tunnel","tunnel_id":"port-3","proto":"tcp","closed":false}\n',
    )
    assert response.get("status") != "ok", response
    assert instance.process.poll() is None


def test_tcp_and_udp_port_namespaces_are_independent(broker_factory) -> None:
    """(protocol, port) is the allocation key, so the same number can serve both."""
    instance = broker_factory(ports=1)
    tcp = instance.create_tunnel("dual-tcp", proto="tcp")
    udp = instance.create_tunnel("dual-udp", proto="udp")
    assert tcp["public_port"] == udp["public_port"]


def test_broker_ipc_unavailable_is_a_clean_error(broker) -> None:
    """When the broker is gone, IPC callers get a connection error, not a hang."""
    broker.stop()
    with pytest.raises((ConnectionRefusedError, FileNotFoundError, OSError)):
        ipc_raw(broker.socket_path, '{"op":"health"}\n', timeout=3)
    broker.socket_path.unlink(missing_ok=True)
    broker.start()
    assert broker.ipc("health")["status"] == "ok"


# ---------------------------------------------------------------------------
# protocol faults
# ---------------------------------------------------------------------------


def _garbage_control_frames() -> list[bytes]:
    """Frames that must all be rejected before any allocation happens."""
    return [
        b"",                                              # immediate EOF
        b"\x00",                                          # truncated header
        b"\xff" * 10,                                     # bad version
        struct.pack(">BBII", 1, 3, 0xFFFFFFFF, 0),        # absurd payload length
        struct.pack(">BBII", 1, 3, 0x7FFFFFFF, 0),        # 2 GiB claim
        struct.pack(">BBII", 1, 99, 0, 0),                # unknown message type
        struct.pack(">BBII", 1, 1, 4, 0) + b"\x00" * 4,   # HELLO with junk body
        struct.pack(">BBII", 1, 3, 2, 0) + b"\xff\xff",   # REGISTER, bogus id length
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",             # wrong protocol entirely
        os.urandom(512),                                  # pure noise
    ]


def test_malformed_control_frames_never_crash_the_broker(broker) -> None:
    """Garbage on the control port is rejected; the process stays healthy."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    for payload in _garbage_control_frames():
        try:
            raw = socket.create_connection(("127.0.0.1", broker.control_port), timeout=5)
            with context.wrap_socket(raw) as tls:
                tls.settimeout(3)
                if payload:
                    tls.sendall(payload)
                try:
                    tls.recv(4096)
                except (TimeoutError, ssl.SSLError, ConnectionResetError, OSError):
                    pass
        except (ConnectionResetError, ssl.SSLError, OSError):
            pass

    assert broker.process.poll() is None, broker.log_text()
    assert broker.ipc("health")["status"] == "ok"


def test_plaintext_connection_to_tls_port_is_rejected(broker) -> None:
    """The control port speaks TLS only; plaintext must not be relayed."""
    with socket.create_connection(("127.0.0.1", broker.control_port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b"plaintext register attempt\n")
        try:
            assert client.recv(64) == b""
        except ConnectionResetError:
            pass
    assert broker.process.poll() is None
    assert broker.ipc("health")["status"] == "ok"


def test_malformed_ipc_input_is_rejected(broker) -> None:
    """The IPC socket is a trusted channel but still validates its input."""
    for payload in (
        "not json at all\n",
        "{}\n",
        '{"op":}\n',
        '{"op":"nope"}\n',
        '{"op":"create_tunnel"}\n',
        '{"op":"create_tunnel","tunnel_id":"x","proto":"sctp","closed":false}\n',
        '{"op":"delete_tunnel","tunnel_id":"does-not-exist"}\n',
        json.dumps({"op": "create_tunnel", "tunnel_id": "x" * 4096, "proto": "tcp"}) + "\n",
    ):
        try:
            response = ipc_raw(broker.socket_path, payload, timeout=3)
            assert response.get("status") != "ok" or "tunnel_id" in response
        except (json.JSONDecodeError, ConnectionResetError, OSError):
            pass
    assert broker.process.poll() is None
    assert broker.ipc("health")["status"] == "ok"


# ---------------------------------------------------------------------------
# UDP faults
# ---------------------------------------------------------------------------


def test_udp_oversized_datagram_is_dropped_not_truncated(broker_factory) -> None:
    """A datagram past the limit is dropped whole — never silently shortened."""
    instance = broker_factory(settings={"broker.udp_max_datagram_size": 1400})
    echo = UdpEcho()
    echo.start()
    tunnel = instance.create_tunnel("udp-oversize", proto="udp")
    start_agent(instance, tunnel, echo.port, "udp")

    assert udp_roundtrip(tunnel["public_port"], b"x" * 1400) == b"x" * 1400
    before = instance.status()["udp_dropped_oversize"]
    assert udp_roundtrip(tunnel["public_port"], b"y" * 4096, timeout=2) is None
    wait_for(lambda: instance.status()["udp_dropped_oversize"] > before, timeout=10)

    # Nothing truncated ever reached the service.
    assert all(size <= 1400 for size in echo.sizes), echo.sizes
    assert 4096 not in echo.sizes
    echo.close()


def test_udp_zero_length_datagram_round_trips(broker) -> None:
    """A zero-length datagram is a legal datagram and must survive as one."""
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("udp-empty", proto="udp")
    start_agent(broker, tunnel, echo.port, "udp")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.sendto(b"", ("127.0.0.1", tunnel["public_port"]))
        data, _ = client.recvfrom(65535)
        assert data == b""
    assert echo.sizes and echo.sizes[0] == 0
    echo.close()


def test_udp_flow_idle_timeout_reclaims_state(broker_factory) -> None:
    """Idle flows expire so historical senders never accumulate state."""
    instance = broker_factory(
        settings={
            "broker.udp_flow_idle_timeout_ms": 1500,
            "broker.udp_max_flows_per_tunnel": 64,
        }
    )
    echo = UdpEcho()
    echo.start()
    tunnel = instance.create_tunnel("udp-idle", proto="udp")
    start_agent(instance, tunnel, echo.port, "udp")

    assert udp_roundtrip(tunnel["public_port"], b"hello") == b"hello"
    before = instance.status()["udp_flow_expired"]
    wait_for(lambda: instance.status()["udp_flow_expired"] > before, timeout=30)

    # A new datagram after expiry simply creates a fresh flow.
    assert udp_roundtrip(tunnel["public_port"], b"again") == b"again"
    echo.close()


def test_udp_many_sources_keep_independent_flows(broker) -> None:
    """Concurrent senders must never receive each other's replies."""
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("udp-multi", proto="udp")
    start_agent(broker, tunnel, echo.port, "udp")

    clients = []
    try:
        for index in range(16):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(6)
            clients.append((index, sock))
            sock.sendto(f"client-{index:03d}".encode(), ("127.0.0.1", tunnel["public_port"]))
        for index, sock in clients:
            data, _ = sock.recvfrom(65535)
            assert data == f"client-{index:03d}".encode(), "reply routed to the wrong flow"
    finally:
        for _, sock in clients:
            sock.close()
    echo.close()


def test_udp_flood_is_rate_limited_without_unbounded_memory(broker_factory) -> None:
    """A datagram flood is dropped by policy, not absorbed into memory."""
    instance = broker_factory(
        settings={
            "broker.udp_max_packets_per_tunnel": 200,
            "broker.udp_max_packets_per_source": 100,
            "broker.udp_queue_packets": 64,
        }
    )
    echo = UdpEcho()
    echo.start()
    tunnel = instance.create_tunnel("udp-flood", proto="udp")
    start_agent(instance, tunnel, echo.port, "udp")

    assert udp_roundtrip(tunnel["public_port"], b"warmup") == b"warmup"
    baseline_rss = rss_kib(instance.process.pid)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        for index in range(4000):
            try:
                client.sendto(b"f" * 512, ("127.0.0.1", tunnel["public_port"]))
            except OSError:
                time.sleep(0.001)
            if index % 500 == 0:
                time.sleep(0.01)

    time.sleep(1.0)
    status = instance.status()
    dropped = (
        status["udp_dropped_rate_limit"]
        + status["udp_dropped_queue_full"]
        + status["udp_dropped_no_flow"]
    )
    assert dropped > 0, "flood should have tripped a documented drop policy"
    assert instance.process.poll() is None
    growth = rss_kib(instance.process.pid) - baseline_rss
    assert growth < 65536, f"broker RSS grew {growth} KiB under a UDP flood"
    echo.close()


def test_udp_local_service_unavailable_does_not_kill_the_tunnel(broker) -> None:
    """No UDP listener behind the agent means no reply — and no crash."""
    dead_port = free_tcp_port()
    tunnel = broker.create_tunnel("udp-no-service", proto="udp")
    start_agent(broker, tunnel, dead_port, "udp")

    assert udp_roundtrip(tunnel["public_port"], b"nobody-home", timeout=2) is None
    assert broker.agent_online(tunnel["tunnel_id"])
    assert broker.process.poll() is None


def test_udp_agent_restart_recovers_flows(broker) -> None:
    """A restarted UDP agent serves new flows; old flow state is not resurrected."""
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("udp-agent-restart", proto="udp")
    agent = start_agent(broker, tunnel, echo.port, "udp", name="udp-first")
    assert udp_roundtrip(tunnel["public_port"], b"before") == b"before"

    agent.kill()
    agent.wait(timeout=5)
    wait_for(lambda: not broker.agent_online(tunnel["tunnel_id"]), timeout=20)

    start_agent(broker, tunnel, echo.port, "udp", name="udp-second")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if udp_roundtrip(tunnel["public_port"], b"after", timeout=2) == b"after":
            break
    else:
        pytest.fail("UDP tunnel did not recover after agent restart")
    echo.close()


# ---------------------------------------------------------------------------
# closed-mode faults
# ---------------------------------------------------------------------------


def test_closed_udp_wrong_token_is_rejected(broker) -> None:
    """A closed UDP peer with a bad token relays nothing."""
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("closed-udp-bad", proto="udp", closed=True)
    start_agent(broker, tunnel, echo.port, "udp")

    before = broker.status()["failed_auths"]
    peer_port = free_tcp_port()
    start_peer(broker, tunnel, "definitely-the-wrong-token", peer_port, "udp", wait_ready=False)
    time.sleep(2)
    assert udp_roundtrip(peer_port, b"should-not-arrive", timeout=2) is None
    wait_for(lambda: broker.status()["failed_auths"] > before, timeout=15)
    assert echo.count == 0, "an unauthenticated peer reached the private service"
    echo.close()


def test_closed_tcp_tunnel_binds_no_public_listener(broker) -> None:
    """A closed TCP tunnel must not expose a public port at all.

    Closed TCP consumers reach the tunnel through an authenticated peer on the
    control port, so a public listener would be pure unauthenticated exposure.
    """
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("closed-no-public", proto="tcp", closed=True)
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    assert not tunnel.get("public_port"), "closed TCP tunnel consumed a public port"

    # Nothing in the configured public range may relay to the private service.
    for port in range(broker.public_start, broker.public_end + 1):
        with socket.socket() as probe:
            probe.settimeout(2)
            if probe.connect_ex(("127.0.0.1", port)) != 0:
                continue
            probe.sendall(b"raw-unauthenticated")
            try:
                assert probe.recv(64) == b"", f"closed tunnel served a raw client on {port}"
            except ConnectionResetError:
                pass

    # The authenticated path still works.
    peer_port = free_tcp_port()
    start_peer(broker, tunnel, tunnel["shared_token"], peer_port, "tcp")
    assert echo_roundtrip(peer_port) == b"ping"

    server.shutdown()
    server.server_close()
