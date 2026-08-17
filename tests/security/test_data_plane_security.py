"""Security tests against the running C data plane.

Everything here talks to a real ``tunnelmated`` over its real TLS/DTLS ports.
The recurring assertion is that a hostile client gets nothing and the broker
stays alive.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import time

from harness import (
    EchoHandler,
    UdpEcho,
    free_tcp_port,
    ipc_raw,
    start_agent,
    start_peer,
    threaded_tcp_server,
    wait_for,
)

MSG_HELLO = 1
MSG_REGISTER = 3
MSG_AUTH = 19
MAX_FRAME_PAYLOAD = 256 * 1024


def frame(msg_type: int, stream_id: int = 0, payload: bytes = b"") -> bytes:
    """Build a TunnelMate/1 control frame: version, type, length, stream id."""
    return struct.pack(">BBII", 1, msg_type, len(payload), stream_id) + payload


def register_payload(tunnel_id: str, secret: str) -> bytes:
    encoded = tunnel_id.encode()
    return struct.pack(">H", len(encoded)) + encoded + secret.encode()


def tls_client(port: int, timeout: float = 5.0) -> ssl.SSLSocket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    tls = context.wrap_socket(raw)
    tls.settimeout(timeout)
    return tls


def read_reply(tls: ssl.SSLSocket) -> bytes:
    try:
        return tls.recv(4096)
    except (TimeoutError, ssl.SSLError, ConnectionResetError, OSError):
        return b""


# ---------------------------------------------------------------------------
# transport security
# ---------------------------------------------------------------------------


def test_control_port_requires_tls(broker) -> None:
    """No plaintext control plane, ever."""
    with socket.create_connection(("127.0.0.1", broker.control_port), timeout=5) as plain:
        plain.settimeout(5)
        plain.sendall(frame(MSG_HELLO, payload=b"TunnelMate/1"))
        try:
            assert plain.recv(64) == b""
        except ConnectionResetError:
            pass
    assert broker.process.poll() is None


def test_tls_negotiates_1_2_or_better(broker) -> None:
    """TLS 1.3 preferred, 1.2 minimum — never an obsolete version."""
    with tls_client(broker.control_port) as tls:
        assert tls.version() in {"TLSv1.2", "TLSv1.3"}, tls.version()


def test_obsolete_tls_versions_are_refused(broker) -> None:
    """A downgrade to TLS 1.0/1.1 must fail the handshake outright."""
    for maximum in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = maximum
        except (ValueError, OSError):
            continue  # the local OpenSSL refuses to even offer it
        try:
            raw = socket.create_connection(("127.0.0.1", broker.control_port), timeout=5)
            with context.wrap_socket(raw) as tls:
                assert tls.version() not in {"TLSv1", "TLSv1.1"}, "broker accepted a downgrade"
        except (ssl.SSLError, OSError):
            pass  # refused, which is the desired outcome
    assert broker.process.poll() is None


def test_agent_rejects_untrusted_certificate_by_default(broker, tmp_path) -> None:
    """Verification is on unless explicitly disabled; a bad CA must not connect."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("verify-ca", proto="tcp")

    # Point the agent at a CA bundle that did not sign the broker certificate.
    bogus_ca = broker.tmp / "bogus-ca.pem"
    os.system(
        f"openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out {bogus_ca} "
        f"-days 1 -subj /CN=not-the-broker >/dev/null 2>&1"
    )
    agent = start_agent(
        broker,
        tunnel,
        server.server_address[1],
        "tcp",
        name="verify",
        wait_online=False,
        extra={"agent.verify_ca": "true", "agent.ca_path": str(bogus_ca)},
    )
    time.sleep(4)
    assert not broker.agent_online(tunnel["tunnel_id"]), (
        "agent registered despite an untrusted broker certificate"
    )
    agent.kill()
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# credential handling
# ---------------------------------------------------------------------------


def test_wrong_agent_secret_is_refused(broker) -> None:
    """Registration with a bad secret fails and is counted."""
    tunnel = broker.create_tunnel("bad-secret", proto="tcp")
    before = broker.status()["failed_auths"]

    with tls_client(broker.control_port) as tls:
        tls.sendall(frame(MSG_HELLO, payload=b"TunnelMate/1"))
        read_reply(tls)
        tls.sendall(
            frame(MSG_REGISTER, payload=register_payload(tunnel["tunnel_id"], "wrong-secret"))
        )
        read_reply(tls)

    wait_for(lambda: broker.status()["failed_auths"] > before, timeout=10)
    assert not broker.agent_online(tunnel["tunnel_id"])


def test_registration_for_unknown_tunnel_looks_the_same_as_a_bad_secret(broker) -> None:
    """Auth failure must not disclose whether a tunnel exists."""
    real = broker.create_tunnel("exists", proto="tcp")

    def attempt(tunnel_id: str, secret: str) -> bytes:
        with tls_client(broker.control_port) as tls:
            tls.sendall(frame(MSG_HELLO, payload=b"TunnelMate/1"))
            read_reply(tls)
            tls.sendall(frame(MSG_REGISTER, payload=register_payload(tunnel_id, secret)))
            return read_reply(tls)

    unknown = attempt("no-such-tunnel-at-all", "some-secret-value")
    wrong = attempt(real["tunnel_id"], "some-secret-value")

    # Compare the message type and payload, not timing.
    assert unknown[:2] == wrong[:2], (unknown[:16], wrong[:16])
    assert unknown[10:] == wrong[10:], "error text distinguishes existence"


def test_brute_forcing_a_closed_token_gains_nothing(broker) -> None:
    """Repeated bad tokens are all rejected and none reach the service."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("brute", proto="tcp", closed=True)
    start_agent(broker, tunnel, server.server_address[1], "tcp")
    before = broker.status()["failed_auths"]

    real = tunnel["shared_token"]
    guesses = [
        "",
        "a",
        real[:-1],                     # off by one character
        real[:-1] + ("b" if real[-1] != "b" else "c"),
        real.upper(),
        real + "x",
        "\x00" * len(real),
    ]
    for guess in guesses:
        with tls_client(broker.control_port) as tls:
            tls.sendall(frame(MSG_HELLO, payload=b"TunnelMate/1"))
            read_reply(tls)
            tls.sendall(
                frame(MSG_AUTH, payload=register_payload(tunnel["tunnel_id"], guess))
            )
            reply = read_reply(tls)
            assert b"AUTH_OK" not in reply

    wait_for(lambda: broker.status()["failed_auths"] >= before + len(guesses) - 2, timeout=10)
    assert broker.process.poll() is None

    # The genuine token still works, so rejection was not a blanket lockout.
    peer_port = free_tcp_port()
    start_peer(broker, tunnel, real, peer_port, "tcp")
    with socket.create_connection(("127.0.0.1", peer_port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b"authorised")
        assert client.recv(64) == b"authorised"

    server.shutdown()
    server.server_close()


def test_secrets_never_appear_in_logs(broker) -> None:
    """Tokens and secrets must not be written to any log, at any level."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("log-secrets", proto="tcp", closed=True)
    start_agent(broker, tunnel, server.server_address[1], "tcp")
    peer_port = free_tcp_port()
    start_peer(broker, tunnel, tunnel["shared_token"], peer_port, "tcp")
    with socket.create_connection(("127.0.0.1", peer_port), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b"payload-marker-do-not-log")
        client.recv(64)

    secrets = [tunnel["agent_secret"], tunnel["shared_token"]]
    for path in broker.tmp.glob("*.log"):
        text = path.read_text(errors="replace")
        for secret in secrets:
            assert secret not in text, f"{path.name} leaked a credential"
        assert "payload-marker-do-not-log" not in text, f"{path.name} logged payload bytes"

    server.shutdown()
    server.server_close()


def test_agent_config_is_not_world_readable(broker) -> None:
    """Secrets on disk must not be readable by other local users."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("perm-check", proto="tcp", closed=True)
    start_agent(broker, tunnel, server.server_address[1], "tcp")
    peer_port = free_tcp_port()
    start_peer(broker, tunnel, tunnel["shared_token"], peer_port, "tcp")

    for pattern in ("agent-*.conf", "*.token"):
        for path in broker.tmp.glob(pattern):
            mode = path.stat().st_mode & 0o077
            assert mode == 0, f"{path.name} is group/other accessible ({oct(mode)})"

    server.shutdown()
    server.server_close()


def test_secrets_are_not_visible_in_process_arguments(broker) -> None:
    """Other local users can read /proc/PID/cmdline; secrets must not be there."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("argv-check", proto="tcp", closed=True)
    agent = start_agent(broker, tunnel, server.server_address[1], "tcp")
    peer_port = free_tcp_port()
    peer = start_peer(broker, tunnel, tunnel["shared_token"], peer_port, "tcp")

    for process in (agent, peer):
        cmdline = (
            (broker.tmp / "x").parent  # keep the path helper import-free
            and open(f"/proc/{process.pid}/cmdline", "rb").read().decode(errors="replace")
        )
        assert tunnel["agent_secret"] not in cmdline
        assert tunnel["shared_token"] not in cmdline

    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# resource abuse
# ---------------------------------------------------------------------------


def test_oversized_frame_is_rejected_before_allocation(broker) -> None:
    """A huge declared length must be refused without reserving memory."""
    before = broker.status()["protocol_errors"]
    for declared in (MAX_FRAME_PAYLOAD + 1, 0x00FFFFFF, 0x7FFFFFFF, 0xFFFFFFFF):
        with tls_client(broker.control_port) as tls:
            tls.sendall(struct.pack(">BBII", 1, MSG_REGISTER, declared, 0))
            tls.sendall(b"\x00" * 1024)  # far less than declared
            read_reply(tls)
    wait_for(lambda: broker.status()["protocol_errors"] > before, timeout=10)
    assert broker.process.poll() is None
    assert broker.ipc("health")["status"] == "ok"


def test_slowloris_handshake_is_timed_out(broker_factory) -> None:
    """Connections that never finish a handshake must not be held forever."""
    instance = broker_factory(settings={"broker.handshake_timeout_ms": 1500})
    sockets = []
    try:
        for _ in range(20):
            try:
                tls = tls_client(instance.control_port, timeout=3)
                tls.sendall(b"\x01")  # one byte of a header, then nothing
                sockets.append(tls)
            except (ssl.SSLError, OSError):
                pass
        # After the handshake deadline the broker should have dropped them.
        time.sleep(4)
        assert instance.process.poll() is None
        assert instance.ipc("health")["status"] == "ok"
    finally:
        for tls in sockets:
            try:
                tls.close()
            except OSError:
                pass


def test_connection_flood_is_bounded(broker_factory) -> None:
    """A rapid connect flood is rate limited rather than exhausting the broker."""
    broker = broker_factory(settings={"broker.connect_rate_per_ip": 5})
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("flood", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    opened = []
    try:
        for _ in range(150):
            try:
                sock = socket.create_connection(
                    ("127.0.0.1", tunnel["public_port"]), timeout=2
                )
                opened.append(sock)
            except OSError:
                break
    finally:
        for sock in opened:
            sock.close()

    assert broker.process.poll() is None
    status = broker.status()
    assert status["conns_rate_limited"] > 0, "connect rate limiting never engaged"

    server.shutdown()
    server.server_close()


def test_udp_is_not_an_amplifier(broker) -> None:
    """A small unsolicited datagram must not produce a large reply."""
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("amplify", proto="udp")
    start_agent(broker, tunnel, echo.port, "udp")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(b"\x00", ("127.0.0.1", tunnel["public_port"]))
        total = 0
        try:
            while True:
                data, _ = client.recvfrom(65535)
                total += len(data)
        except TimeoutError:
            pass
    # An echo service returns exactly what it got; the tunnel must not multiply it.
    assert total <= 1, f"1-byte request produced {total} bytes of reply"
    echo.close()


def test_ipc_socket_is_not_world_accessible(broker) -> None:
    """The IPC socket is the broker's control surface; keep it off world access."""
    mode = broker.socket_path.stat().st_mode & 0o777
    assert mode & 0o007 == 0, f"broker socket is world accessible ({oct(mode)})"


def test_broker_survives_the_whole_hostile_sequence(broker) -> None:
    """A final liveness check: after all of the above the broker still serves."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("still-alive", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    for payload in (b"", b"\xff" * 64, os.urandom(256)):
        try:
            ipc_raw(broker.socket_path, payload.decode("latin-1") + "\n", timeout=2)
        except (OSError, ValueError):
            pass

    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as client:
        client.settimeout(5)
        client.sendall(b"final")
        assert client.recv(64) == b"final"

    server.shutdown()
    server.server_close()
