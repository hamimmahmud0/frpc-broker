"""Concurrency and resource-bound tests.

Sizes are deliberately configurable so a constrained CI machine can run a
smaller version of the same scenario. Override with:

    TUNNELMATE_LOAD_TUNNELS, TUNNELMATE_LOAD_CONNECTIONS, TUNNELMATE_LOAD_FLOWS
"""

from __future__ import annotations

import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from harness import (
    EchoHandler,
    UdpEcho,
    free_tcp_port,
    open_fds,
    rss_kib,
    start_agent,
    start_peer,
    threaded_tcp_server,
    wait_for,
)

TUNNELS = int(os.getenv("TUNNELMATE_LOAD_TUNNELS", "40"))
CONNECTIONS = int(os.getenv("TUNNELMATE_LOAD_CONNECTIONS", "100"))
FLOWS = int(os.getenv("TUNNELMATE_LOAD_FLOWS", "128"))


def echo_once(port: int, payload: bytes, timeout: float = 20.0) -> bytes:
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


def test_many_idle_tunnels_stay_cheap(broker_factory) -> None:
    """Idle tunnels must cost almost nothing — this is a 2 GB VPS."""
    broker = broker_factory(
        ports=TUNNELS + 4, settings={"broker.max_tunnels": TUNNELS + 8}
    )
    baseline = rss_kib(broker.process.pid)

    for index in range(TUNNELS):
        broker.create_tunnel(f"idle-{index:04d}", proto="tcp" if index % 2 else "udp")

    assert len(broker.tunnels()) == TUNNELS
    time.sleep(1)
    growth = rss_kib(broker.process.pid) - baseline
    per_tunnel = growth / TUNNELS
    print(
        f"\nidle_tunnels count={TUNNELS} rss_growth_kib={growth} "
        f"per_tunnel_kib={per_tunnel:.1f}"
    )
    assert per_tunnel < 256, f"{per_tunnel:.1f} KiB per idle tunnel is too much"
    assert broker.process.poll() is None


def test_simultaneous_connections_on_one_tunnel(broker_factory) -> None:
    """Many concurrent streams through a single tunnel, all data intact."""
    # The per-IP connect limiter would otherwise reject this burst, which is the
    # point of the limiter; a real deployment raises it for trusted load.
    broker = broker_factory(
        settings={
            "broker.connect_rate_per_ip": CONNECTIONS * 10,
            "broker.max_streams_per_tunnel": CONNECTIONS * 2,
            "broker.max_streams": CONNECTIONS * 4,
            "broker.max_pending_streams": CONNECTIONS * 2,
        }
    )
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("concurrent", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    payloads = [f"stream-{index:05d}".encode() * 64 for index in range(CONNECTIONS)]
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=min(64, CONNECTIONS)) as pool:
        results = list(pool.map(lambda p: echo_once(tunnel["public_port"], p), payloads))
    elapsed = time.monotonic() - started

    mismatches = [i for i, (got, want) in enumerate(zip(results, payloads, strict=True)) if got != want]
    assert not mismatches, f"{len(mismatches)} streams returned wrong data"
    print(
        f"\nconcurrent_streams count={CONNECTIONS} seconds={elapsed:.2f} "
        f"conns_per_sec={CONNECTIONS / elapsed:.1f} "
        f"broker_rss_kib={rss_kib(broker.process.pid)}"
    )

    wait_for(lambda: broker.tunnel(tunnel["tunnel_id"])["streams_active"] == 0, timeout=30)
    server.shutdown()
    server.server_close()


def test_rapid_connect_disconnect_churn(broker_factory) -> None:
    """Short-lived connections must not leak descriptors or streams."""
    broker = broker_factory(settings={"broker.connect_rate_per_ip": 10000})
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("churn", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    echo_once(tunnel["public_port"], b"warmup")
    baseline_fds = open_fds(broker.process.pid)

    for _ in range(200):
        try:
            sock = socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=5)
            sock.close()
        except OSError:
            pass

    wait_for(lambda: broker.tunnel(tunnel["tunnel_id"])["streams_active"] == 0, timeout=30)
    grown = open_fds(broker.process.pid) - baseline_fds
    print(f"\nchurn cycles=200 fd_growth={grown}")
    assert grown < 32, f"descriptor growth after 200 connect/close cycles: {grown}"
    assert broker.process.poll() is None
    assert echo_once(tunnel["public_port"], b"still-working") == b"still-working"

    server.shutdown()
    server.server_close()


def test_slow_consumer_does_not_grow_broker_memory(broker) -> None:
    """Backpressure, not buffering: a stalled reader must stall the producer."""

    class Firehose(EchoHandler):
        def handle(self) -> None:  # type: ignore[override]
            block = os.urandom(65536)
            try:
                while True:
                    self.request.sendall(block)
            except OSError:
                return

    server = threaded_tcp_server(Firehose)
    tunnel = broker.create_tunnel("slow-consumer", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    with socket.create_connection(("127.0.0.1", tunnel["public_port"]), timeout=10) as client:
        client.settimeout(10)
        assert client.recv(4096), "no data flowed at all"
        baseline = rss_kib(broker.process.pid)
        # Read nothing for a while; the broker must push back, not buffer.
        time.sleep(6)
        growth = rss_kib(broker.process.pid) - baseline
        print(f"\nslow_consumer stalled_seconds=6 broker_rss_growth_kib={growth}")
        assert growth < 32768, f"broker grew {growth} KiB while a reader stalled"

    assert broker.process.poll() is None
    server.shutdown()
    server.server_close()


def test_many_udp_flows_are_routed_independently(broker_factory) -> None:
    """Each source tuple is its own flow; replies must never cross over."""
    broker = broker_factory(
        settings={
            "broker.udp_max_flows_per_tunnel": FLOWS * 2,
            "broker.udp_flow_creation_rate": FLOWS * 4,
            "broker.udp_max_packets_per_tunnel": FLOWS * 20,
            "broker.udp_flow_idle_timeout_ms": 30000,
        }
    )
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel("udp-flows", proto="udp")
    start_agent(broker, tunnel, echo.port, "udp")

    clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(FLOWS)]
    wrong = 0
    lost = 0
    try:
        for index, sock in enumerate(clients):
            sock.settimeout(10)
            sock.sendto(f"flow-{index:05d}".encode(), ("127.0.0.1", tunnel["public_port"]))
        for index, sock in enumerate(clients):
            try:
                data, _ = sock.recvfrom(65535)
            except TimeoutError:
                lost += 1
                continue
            if data != f"flow-{index:05d}".encode():
                wrong += 1
    finally:
        for sock in clients:
            sock.close()

    print(f"\nudp_flows count={FLOWS} lost={lost} misrouted={wrong}")
    assert wrong == 0, f"{wrong} replies went to the wrong flow"
    assert lost <= FLOWS * 0.05, f"{lost}/{FLOWS} flows got no reply on loopback"
    echo.close()


def test_dns_like_request_reply_from_many_clients(broker_factory) -> None:
    """Short request, short reply, many independent senders — the DNS shape."""
    broker = broker_factory(
        settings={
            "broker.udp_max_flows_per_tunnel": 512,
            "broker.udp_flow_creation_rate": 512,
            "broker.udp_max_packets_per_tunnel": 20000,
            "broker.udp_max_packets_per_source": 2000,
        }
    )

    def responder(query: bytes) -> bytes:
        # Mimic a resolver: echo the 2-byte id, then a fixed answer.
        return query[:2] + b"|answer"

    echo = UdpEcho(transform=responder)
    echo.start()
    tunnel = broker.create_tunnel("dns-like", proto="udp")
    start_agent(broker, tunnel, echo.port, "udp")

    errors: list[str] = []

    def one_client(index: int) -> None:
        query_id = index.to_bytes(2, "big")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            for _ in range(3):
                sock.sendto(query_id + b"question", ("127.0.0.1", tunnel["public_port"]))
                try:
                    data, _ = sock.recvfrom(4096)
                except TimeoutError:
                    continue
                if data != query_id + b"|answer":
                    errors.append(f"client {index} got {data!r}")
                return
            errors.append(f"client {index} got no answer")

    threads = [threading.Thread(target=one_client, args=(i,)) for i in range(64)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    print(f"\ndns_like clients=64 errors={len(errors)}")
    assert not errors, errors[:5]
    echo.close()


def test_wrong_closed_tokens_at_volume_are_all_rejected(broker) -> None:
    """A guessing storm must be rejected without disturbing legitimate use."""
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("token-storm", proto="tcp", closed=True)
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    good_port = free_tcp_port()
    start_peer(broker, tunnel, tunnel["shared_token"], good_port, "tcp")
    assert echo_once(good_port, b"before-storm") == b"before-storm"

    before = broker.status()["failed_auths"]
    bad_ports = []
    for index in range(8):
        port = free_tcp_port()
        bad_ports.append(port)
        start_peer(broker, tunnel, f"wrong-token-number-{index:04d}", port, "tcp", wait_ready=False)
    time.sleep(3)

    for port in bad_ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                client.settimeout(3)
                client.sendall(b"should-not-reach")
                assert client.recv(64) == b""
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError, OSError):
            pass

    assert broker.status()["failed_auths"] > before
    assert echo_once(good_port, b"after-storm") == b"after-storm"

    server.shutdown()
    server.server_close()


@pytest.mark.extended
@pytest.mark.skipif(
    "TUNNELMATE_LOAD_EXTENDED" not in os.environ,
    reason="set TUNNELMATE_LOAD_EXTENDED=1 for the 256-connection scenario",
)
def test_256_simultaneous_connections(broker_factory) -> None:
    """The specification's larger concurrency target."""
    broker = broker_factory(
        settings={
            "broker.max_streams": 1024,
            "broker.max_streams_per_tunnel": 512,
            "broker.max_pending_streams": 512,
            "broker.connect_rate_per_ip": 2000,
        }
    )
    server = threaded_tcp_server(EchoHandler)
    tunnel = broker.create_tunnel("big-concurrency", proto="tcp")
    start_agent(broker, tunnel, server.server_address[1], "tcp")

    payloads = [f"conn-{index:05d}".encode() * 32 for index in range(256)]
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=128) as pool:
        results = list(
            pool.map(lambda p: echo_once(tunnel["public_port"], p, timeout=60), payloads)
        )
    elapsed = time.monotonic() - started
    assert results == payloads
    print(
        f"\nconnections_256 seconds={elapsed:.2f} "
        f"conns_per_sec={256 / elapsed:.1f} broker_rss_kib={rss_kib(broker.process.pid)}"
    )
    server.shutdown()
    server.server_close()
