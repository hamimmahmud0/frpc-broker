from __future__ import annotations

import socket
import socketserver
import threading

import tunnelmate
from pydantic import ValidationError
from tunnelmate.client import _HandlerProxy


def test_config_dict_api() -> None:
    tunnel = tunnelmate.new(
        "https://broker.example",
        {
            "host": "127.0.0.1",
            "port": 5675,
            "protocol": "tcp",
            "scope": "open",
            "service_name": "Example",
            "service_id": "example",
            "llms": "https://example.test/llms.txt",
            "attributes": {"version": 1},
        },
    )
    assert tunnel.config.port == 5675
    assert tunnel.config.attributes == {"version": 1}
    tunnel.close()


def test_typed_config_and_protocol_validation() -> None:
    config = tunnelmate.TunnelConfig(port=5000, protocol="udp", scope="closed")
    assert config.protocol == "udp"
    try:
        tunnelmate.TunnelConfig(port=5000, protocol="icmp")
    except ValidationError:
        pass
    else:
        raise AssertionError("invalid protocol accepted")


def test_peer_factory() -> None:
    peer = tunnelmate.connect(
        "tunnel://broker.example:7000/tun_abc",
        token="shared-secret-value",
        local_port=9000,
    )
    assert peer.config.local_port == 9000
    peer.stop()


def test_message_handler_proxy_transforms_both_directions() -> None:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            while data := self.request.recv(65536):
                self.request.sendall(data + b"-service")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def transform(direction: str, data: bytes, context: object) -> bytes:
        del context
        suffix = b"-in" if direction == "peer_to_service" else b"-out"
        return data + suffix

    proxy = _HandlerProxy("127.0.0.1", server.server_address[1], transform)
    proxy.start()
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=2) as client:
        client.sendall(b"hello")
        assert client.recv(128) == b"hello-in-service-out"
    proxy.close()
    server.shutdown()
    server.server_close()


def test_udp_handler_proxy_preserves_datagram_boundaries() -> None:
    """One datagram in must produce exactly one handler call and one datagram out.

    A stream-shaped proxy would coalesce these, which is precisely what a UDP
    tunnel must never do.
    """
    import socket
    import threading

    from tunnelmate.client import _UdpHandlerProxy

    service = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    service.bind(("127.0.0.1", 0))
    service.settimeout(5)
    seen: list[int] = []
    stop = threading.Event()

    def echo() -> None:
        while not stop.is_set():
            try:
                data, addr = service.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            seen.append(len(data))
            service.sendto(b"reply:" + data, addr)

    threading.Thread(target=echo, daemon=True).start()

    calls: list[tuple[str, int, str]] = []

    def handler(direction, datagram, context):
        calls.append((direction, len(datagram), context.protocol))
        assert context.remote_ip == "127.0.0.1"
        assert context.flow_id
        return datagram

    proxy = _UdpHandlerProxy(
        "127.0.0.1", service.getsockname()[1], handler, tunnel_id="tun_test"
    )
    proxy.start()
    try:
        sizes = (1, 57, 256, 1200)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            for size in sizes:
                payload = bytes([size % 251]) * size
                client.sendto(payload, ("127.0.0.1", proxy.port))
                reply, _ = client.recvfrom(65535)
                assert reply == b"reply:" + payload, f"size {size} was altered"
        assert seen == list(sizes), f"boundaries changed: {seen}"
        assert [c[0] for c in calls].count("peer_to_service") == len(sizes)
        assert all(c[2] == "udp" for c in calls)
    finally:
        stop.set()
        proxy.close()
        service.close()


def test_udp_handler_can_drop_a_datagram() -> None:
    """Returning None drops exactly that datagram and nothing else."""
    import socket
    import threading

    from tunnelmate.client import _UdpHandlerProxy

    service = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    service.bind(("127.0.0.1", 0))
    service.settimeout(5)
    received: list[bytes] = []
    stop = threading.Event()

    def sink() -> None:
        while not stop.is_set():
            try:
                data, addr = service.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            received.append(data)
            service.sendto(b"ack", addr)

    threading.Thread(target=sink, daemon=True).start()

    def handler(direction, datagram, context):
        return None if datagram == b"drop-me" else datagram

    proxy = _UdpHandlerProxy("127.0.0.1", service.getsockname()[1], handler)
    proxy.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(b"drop-me", ("127.0.0.1", proxy.port))
            try:
                client.recvfrom(65535)
                raise AssertionError("dropped datagram still reached the service")
            except TimeoutError:
                pass
            client.sendto(b"keep-me", ("127.0.0.1", proxy.port))
            assert client.recvfrom(65535)[0] == b"ack"
        assert received == [b"keep-me"]
    finally:
        stop.set()
        proxy.close()
        service.close()
