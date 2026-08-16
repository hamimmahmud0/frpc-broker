from __future__ import annotations

import hashlib
import json
import os
import random
import socket
import socketserver
import subprocess
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BUILD = Path(os.getenv("TUNNELMATE_BUILD_DIR", ROOT / "build"))
STREAM_BLOCK = 65536


def deterministic_bytes(offset: int, length: int) -> bytes:
    output = bytearray()
    while length:
        block_number = offset // STREAM_BLOCK
        within = offset % STREAM_BLOCK
        block = block_number.to_bytes(8, "big") * (STREAM_BLOCK // 8)
        take = min(length, STREAM_BLOCK - within)
        output.extend(block[within : within + take])
        offset += take
        length -= take
    return bytes(output)


def free_tcp_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_public_pair() -> int:
    for _ in range(1000):
        port = random.randint(22000, 58000)
        tcp = socket.socket()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp.bind(("127.0.0.1", port))
            udp.bind(("127.0.0.1", port))
            tcp2 = socket.socket()
            udp2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                tcp2.bind(("127.0.0.1", port + 1))
                udp2.bind(("127.0.0.1", port + 1))
                return port
            finally:
                tcp2.close()
                udp2.close()
        except OSError:
            continue
        finally:
            tcp.close()
            udp.close()
    raise RuntimeError("no free public ports")


def wait_for(predicate, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise TimeoutError("condition did not become true")


def ipc(path: Path, op: str, **values):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(3)
        sock.connect(str(path))
        sock.sendall((json.dumps({"op": op, **values}) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            data += sock.recv(65536)
    response = json.loads(data)
    assert response["status"] == "ok", response
    return response


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class HashSinkHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        digest = hashlib.sha256()
        total = 0
        first_mismatch = -1
        mismatch_actual = mismatch_expected = -1
        mismatch_window = expected_window = "-"
        while data := self.request.recv(65536):
            if first_mismatch < 0:
                wanted = deterministic_bytes(total, len(data))
                if data != wanted:
                    index = next(
                        i for i, pair in enumerate(zip(data, wanted, strict=True))
                        if pair[0] != pair[1]
                    )
                    first_mismatch = total + index
                    mismatch_actual = data[index]
                    mismatch_expected = wanted[index]
                    mismatch_window = data[index : index + 16].hex()
                    expected_window = wanted[index : index + 16].hex()
            digest.update(data)
            total += len(data)
        self.request.sendall(
            f"{total} {digest.hexdigest()} {first_mismatch} "
            f"{mismatch_actual} {mismatch_expected} {mismatch_window} "
            f"{expected_window}\n".encode()
        )


class UdpEcho(threading.Thread):
    def __init__(self) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()

    def run(self) -> None:
        self.sock.settimeout(0.1)
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
                self.sock.sendto(data, addr)
            except TimeoutError:
                pass

    def close(self) -> None:
        self.stop_event.set()
        self.join(timeout=2)
        self.sock.close()


@pytest.fixture
def data_plane(tmp_path: Path):
    control_port = free_tcp_port()
    public_start = free_public_pair()
    cert, key = tmp_path / "broker.crt", tmp_path / "broker.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    broker_sock = tmp_path / "broker.sock"
    broker_conf = tmp_path / "broker.conf"
    broker_conf.write_text(
        "\n".join(
            [
                "broker.listen_host = 127.0.0.1",
                f"broker.control_port = {control_port}",
                f"broker.public_port_start = {public_start}",
                f"broker.public_port_end = {public_start + 1}",
                f"broker.tls_cert = {cert}",
                f"broker.tls_key = {key}",
                f"broker.hmac_key_file = {tmp_path / 'hmac.key'}",
                f"broker.broker_socket = {broker_sock}",
                "broker.log_level = debug",
                "broker.shutdown_grace_ms = 50",
            ]
        )
        + "\n"
    )
    stderr = (tmp_path / "broker.log").open("wb")
    env = {
        **os.environ,
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:quarantine_size_mb=16",
    }
    broker = subprocess.Popen(
        [str(BUILD / "broker" / "tunnelmated"), "-c", str(broker_conf)],
        stdout=subprocess.DEVNULL,
        stderr=stderr,
        env=env,
    )
    wait_for(lambda: broker_sock.exists() or broker.poll() is not None)
    if broker.poll() is not None:
        stderr.close()
        pytest.fail((tmp_path / "broker.log").read_text(errors="replace"))
    processes: list[subprocess.Popen] = []
    yield {
        "tmp": tmp_path,
        "broker": broker,
        "broker_sock": broker_sock,
        "control_port": control_port,
        "processes": processes,
        "env": env,
    }
    for process in processes:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
    if broker.poll() is None:
        broker.terminate()
    try:
        broker.wait(timeout=3)
    except subprocess.TimeoutExpired:
        broker.kill()
    stderr.close()
    if broker.returncode not in {0, -15}:
        pytest.fail((tmp_path / "broker.log").read_text(errors="replace"))


def start_agent(ctx, tunnel, local_port: int, protocol: str):
    conf = ctx["tmp"] / f"agent-{protocol}.conf"
    conf.write_text(
        "\n".join(
            [
                f"agent.tunnel_id = {tunnel['tunnel_id']}",
                f"agent.agent_secret = {tunnel['agent_secret']}",
                "agent.local_host = 127.0.0.1",
                f"agent.local_port = {local_port}",
                "agent.broker_host = 127.0.0.1",
                f"agent.broker_port = {ctx['control_port']}",
                f"agent.broker_udp_port = {tunnel['public_port']}",
                f"agent.protocol = {protocol}",
                "agent.verify_ca = false",
                "agent.log_level = debug",
            ]
        )
        + "\n"
    )
    log = (ctx["tmp"] / f"agent-{protocol}.log").open("wb")
    process = subprocess.Popen(
        [str(BUILD / "agent" / "tunnelmate-agent"), "-c", str(conf)],
        stdout=subprocess.DEVNULL,
        stderr=log,
        env=ctx["env"],
    )
    process._tm_log = log  # type: ignore[attr-defined]
    ctx["processes"].append(process)
    wait_for(
        lambda: (
            process.poll() is not None
            or ipc(ctx["broker_sock"], "get_tunnels")["tunnels"][0].get("agent_online")
        ),
        timeout=10,
    )
    assert process.poll() is None, (ctx["tmp"] / f"agent-{protocol}.log").read_text()
    return process


def start_peer(ctx, tunnel, token: str, local_port: int, protocol: str):
    token_file = ctx["tmp"] / f"peer-{protocol}-{local_port}.token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    remote_port = tunnel["public_port"] if protocol == "udp" else ctx["control_port"]
    log_path = ctx["tmp"] / f"peer-{protocol}-{local_port}.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [
            str(BUILD / "peer" / "tunnelmate-peer"),
            "connect",
            f"tunnel://127.0.0.1:{remote_port}/{tunnel['tunnel_id']}",
            "--token-file",
            str(token_file),
            "--listen",
            f"127.0.0.1:{local_port}",
            "--protocol",
            protocol,
            "--no-verify-ca",
            "--log-level",
            "debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=log,
        env=ctx["env"],
    )
    process._tm_log = log  # type: ignore[attr-defined]
    ctx["processes"].append(process)
    if protocol == "tcp":
        wait_for(
            lambda: process.poll() is not None or _port_is_open(local_port), timeout=5
        )
    else:
        wait_for(
            lambda: (
                process.poll() is not None
                or "udp_authed" in log_path.read_text(errors="replace")
            ),
            timeout=10,
        )
    assert process.poll() is None, log_path.read_text(errors="replace")
    return process


def _port_is_open(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


def test_open_tcp(data_plane) -> None:
    ctx = data_plane
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    tunnel = ipc(
        ctx["broker_sock"],
        "create_tunnel",
        tunnel_id="open-tcp-test",
        proto="tcp",
        closed=False,
    )
    start_agent(ctx, tunnel, server.server_address[1], "tcp")
    payload = os.urandom(1024 * 1024)
    with socket.create_connection(
        ("127.0.0.1", tunnel["public_port"]), timeout=5
    ) as client:
        client.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = client.recv(65536)
            assert chunk
            received.extend(chunk)
    assert received == payload
    ipc(ctx["broker_sock"], "delete_tunnel", tunnel_id=tunnel["tunnel_id"])
    server.shutdown()
    server.server_close()


def test_open_udp_preserves_datagrams(data_plane) -> None:
    ctx = data_plane
    echo = UdpEcho()
    echo.start()
    tunnel = ipc(
        ctx["broker_sock"],
        "create_tunnel",
        tunnel_id="open-udp-test",
        proto="udp",
        closed=False,
    )
    start_agent(ctx, tunnel, echo.port, "udp")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        for size in (1, 57, 256, 1200, 1400):
            payload = os.urandom(size)
            client.sendto(payload, ("127.0.0.1", tunnel["public_port"]))
            received, _ = client.recvfrom(65535)
            assert received == payload
    echo.close()


def test_closed_tcp_rejects_wrong_token_and_relays(data_plane) -> None:
    ctx = data_plane
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tunnel = ipc(
        ctx["broker_sock"],
        "create_tunnel",
        tunnel_id="closed-tcp-test",
        proto="tcp",
        closed=True,
    )
    start_agent(ctx, tunnel, server.server_address[1], "tcp")

    wrong_port = free_tcp_port()
    start_peer(ctx, tunnel, "wrong-token-that-is-long-enough", wrong_port, "tcp")
    with socket.create_connection(("127.0.0.1", wrong_port), timeout=3) as client:
        client.settimeout(2)
        client.sendall(b"must-not-reach-service")
        try:
            assert client.recv(128) == b""
        except ConnectionResetError:
            pass

    peer_port = free_tcp_port()
    start_peer(ctx, tunnel, tunnel["shared_token"], peer_port, "tcp")
    payload = os.urandom(256 * 1024)
    with socket.create_connection(("127.0.0.1", peer_port), timeout=3) as client:
        client.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = client.recv(65536)
            assert chunk
            received.extend(chunk)
    assert received == payload
    ipc(ctx["broker_sock"], "delete_tunnel", tunnel_id=tunnel["tunnel_id"])
    server.shutdown()
    server.server_close()


def test_closed_udp_preserves_datagrams(data_plane) -> None:
    ctx = data_plane
    echo = UdpEcho()
    echo.start()
    tunnel = ipc(
        ctx["broker_sock"],
        "create_tunnel",
        tunnel_id="closed-udp-test",
        proto="udp",
        closed=True,
    )
    start_agent(ctx, tunnel, echo.port, "udp")
    peer_port = free_tcp_port()
    start_peer(ctx, tunnel, tunnel["shared_token"], peer_port, "udp")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.5)
        for size in (1, 57, 256, 1200, 1400):
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
    ipc(ctx["broker_sock"], "delete_tunnel", tunnel_id=tunnel["tunnel_id"])


@pytest.mark.skipif(
    "TUNNELMATE_LARGE_BYTES" not in os.environ,
    reason="set TUNNELMATE_LARGE_BYTES=6442450944 for the extended stream test",
)
def test_large_tcp_stream_without_spooling(data_plane) -> None:
    ctx = data_plane
    count = int(os.environ["TUNNELMATE_LARGE_BYTES"])
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), HashSinkHandler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    tunnel = ipc(
        ctx["broker_sock"],
        "create_tunnel",
        tunnel_id="large-tcp-test",
        proto="tcp",
        closed=False,
    )
    agent = start_agent(ctx, tunnel, server.server_address[1], "tcp")
    expected = hashlib.sha256()
    peak_broker = peak_agent = 0
    started = time.monotonic()
    with socket.create_connection(
        ("127.0.0.1", tunnel["public_port"]), timeout=10
    ) as client:
        client.settimeout(300)
        left = count
        while left:
            offset = count - left
            chunk = deterministic_bytes(offset, min(left, STREAM_BLOCK))
            client.sendall(chunk)
            expected.update(chunk)
            left -= len(chunk)
            if left % (16 * 1024 * 1024) == 0:
                peak_broker = max(peak_broker, _rss_kib(ctx["broker"].pid))
                peak_agent = max(peak_agent, _rss_kib(agent.pid))
        client.shutdown(socket.SHUT_WR)
        response = b""
        while not response.endswith(b"\n"):
            chunk = client.recv(4096)
            assert chunk, "tunnel closed before the hash sink response"
            response += chunk
    remote_count, remote_hash, first_mismatch, actual, wanted, actual_window, wanted_window = (
        response.decode().strip().split()
    )
    elapsed = time.monotonic() - started
    assert int(remote_count) == count
    assert int(first_mismatch) == -1, (
        f"first mismatch at {first_mismatch}: got {actual}, expected {wanted}"
        f"; got {actual_window}, expected {wanted_window}"
    )
    assert remote_hash == expected.hexdigest()
    print(
        f"large_stream bytes={count} seconds={elapsed:.3f} "
        f"MiB/s={count / elapsed / 1048576:.2f} "
        f"broker_peak_rss_kib={peak_broker} agent_peak_rss_kib={peak_agent} "
        f"sha256={remote_hash}"
    )
    server.shutdown()
    server.server_close()


def _rss_kib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        return 0
    return 0
