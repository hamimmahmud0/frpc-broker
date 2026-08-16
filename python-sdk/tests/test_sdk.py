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
