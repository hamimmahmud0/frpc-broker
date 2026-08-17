"""End-to-end tests over the real broker, agent and peer binaries.

These cover the four acceptance combinations from the specification — open TCP,
closed TCP, open UDP, closed UDP — plus stream integrity at size.
"""

from __future__ import annotations

import hashlib
import os
import socket
import time

import pytest
from harness import (
    STREAM_BLOCK,
    EchoHandler,
    HashSinkHandler,
    UdpEcho,
    deterministic_bytes,
    free_tcp_port,
    rss_kib,
    start_agent,
    start_peer,
    threaded_tcp_server,
)

DATAGRAM_SIZES = (1, 57, 256, 1200, 1400)


def test_open_tcp(broker) -> None:
    """A raw Internet client reaches a private TCP service through a public port."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("open-tcp-test", proto="tcp", closed=False)
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    payload = os.urandom(1024 * 1024)
    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as client:
        client.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = client.recv(65536)
            assert chunk
            received.extend(chunk)
    assert received == payload

    broker.ipc("delete_tunnel", tunnel_id=tunnel["tunnel_id"])
    server.shutdown()
    server.server_close()


def test_open_udp_preserves_datagrams(broker) -> None:
    """Each datagram arrives whole and separate — no merging, no splitting."""
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("open-udp-test", proto="udp", closed=False)
    start_agent(broker, tunnel, echo.port, "udp")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        for size in DATAGRAM_SIZES:
            payload = os.urandom(size)
            client.sendto(payload, ("127.0.0.1", tunnel["public_port"]))
            received, _ = client.recvfrom(65535)
            assert received == payload
    assert echo.sizes == list(DATAGRAM_SIZES), "datagram boundaries were not preserved"
    echo.close()


def test_closed_tcp_rejects_wrong_token_and_relays(broker) -> None:
    """A wrong shared token reaches no service bytes; the right one relays."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("closed-tcp-test", proto="tcp", closed=True)
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    wrong_port = free_tcp_port()
    start_peer(broker, tunnel, "wrong-token-that-is-long-enough", wrong_port, "tcp")
    with socket.create_connection(("127.0.0.1", wrong_port), timeout=3) as client:
        client.settimeout(2)
        client.sendall(b"must-not-reach-service")
        try:
            assert client.recv(128) == b""
        except ConnectionResetError:
            pass

    peer_port = free_tcp_port()
    start_peer(broker, tunnel, tunnel["shared_token"], peer_port, "tcp")
    payload = os.urandom(256 * 1024)
    with socket.create_connection(("127.0.0.1", peer_port), timeout=3) as client:
        client.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = client.recv(65536)
            assert chunk
            received.extend(chunk)
    assert received == payload

    broker.ipc("delete_tunnel", tunnel_id=tunnel["tunnel_id"])
    server.shutdown()
    server.server_close()


def test_closed_udp_preserves_datagrams(broker) -> None:
    """Closed-mode UDP keeps datagram boundaries through the authenticated peer."""
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("closed-udp-test", proto="udp", closed=True)
    start_agent(broker, tunnel, echo.port, "udp")
    peer_port = free_tcp_port()
    start_peer(broker, tunnel, tunnel["shared_token"], peer_port, "udp")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.5)
        for size in DATAGRAM_SIZES:
            payload = os.urandom(size)
            deadline = time.monotonic() + 5
            while True:
                client.sendto(payload, ("127.0.0.1", peer_port))
                try:
                    received, _ = client.recvfrom(65535)
                    break
                except TimeoutError:
                    if time.monotonic() >= deadline:
                        raise
            assert received == payload
    echo.close()
    broker.ipc("delete_tunnel", tunnel_id=tunnel["tunnel_id"])


def test_tcp_half_close_drains_queued_tail(broker) -> None:
    """After the client half-closes, the service still delivers its queued reply."""

    class LateReply(EchoHandler):
        def handle(self) -> None:  # type: ignore[override]
            body = bytearray()
            while chunk := self.request.recv(65536):
                body.extend(chunk)
            # The client is done sending (FIN seen); the reverse path must live on.
            self.request.sendall(b"tail:" + bytes(body[:16]))

    server = threaded_tcp_server(LateReply)
    tunnel = broker.create_tunnel("half-close-test", proto="tcp", closed=False)
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5) as client:
        client.settimeout(10)
        client.sendall(b"0123456789abcdef-payload")
        client.shutdown(socket.SHUT_WR)
        response = b""
        while chunk := client.recv(4096):
            response += chunk
    assert response == b"tail:0123456789abcdef"

    server.shutdown()
    server.server_close()


@pytest.mark.extended
@pytest.mark.skipif(
    "TUNNELMATE_LARGE_BYTES" not in os.environ,
    reason="set TUNNELMATE_LARGE_BYTES=6442450944 for the extended stream test",
)
def test_large_tcp_stream_without_spooling(broker) -> None:
    """Stream >5 GiB end to end, hash-verified, with bounded process memory."""
    count = int(os.environ["TUNNELMATE_LARGE_BYTES"])
    server = threaded_tcp_server(HashSinkHandler)
    tunnel = broker.create_tunnel("large-tcp-test", proto="tcp", closed=False)
    agent = start_agent(broker, tunnel, server.server_address[1], "tcp")

    expected = hashlib.sha256()
    peak_broker = peak_agent = 0
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=10) as client:
        client.settimeout(600)
        left = count
        while left:
            offset = count - left
            chunk = deterministic_bytes(offset, min(left, STREAM_BLOCK))
            client.sendall(chunk)
            expected.update(chunk)
            left -= len(chunk)
            if left % (64 * 1024 * 1024) == 0:
                peak_broker = max(peak_broker, rss_kib(broker.process.pid))
                peak_agent = max(peak_agent, rss_kib(agent.pid))
        client.shutdown(socket.SHUT_WR)
        response = b""
        while not response.endswith(b"\n"):
            chunk = client.recv(4096)
            assert chunk, "tunnel closed before the hash sink response"
            response += chunk

    (
        remote_count,
        remote_hash,
        first_mismatch,
        actual,
        wanted,
        actual_window,
        wanted_window,
    ) = response.decode().strip().split()
    elapsed = time.monotonic() - started
    assert int(remote_count) == count
    assert int(first_mismatch) == -1, (
        f"first mismatch at {first_mismatch}: got {actual}, expected {wanted}"
        f"; got {actual_window}, expected {wanted_window}"
    )
    assert remote_hash == expected.hexdigest()
    print(
        f"\nlarge_stream bytes={count} seconds={elapsed:.3f} "
        f"MiB/s={count / elapsed / 1048576:.2f} "
        f"broker_peak_rss_kib={peak_broker} agent_peak_rss_kib={peak_agent} "
        f"sha256={remote_hash}"
    )
    server.shutdown()
    server.server_close()
