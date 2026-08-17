"""Shared fixtures and helpers for every TunnelMate test suite.

The integration, failure, security and load suites all need the same thing: a
real ``tunnelmated`` listening on loopback with a throwaway certificate, plus
helpers to attach real ``tunnelmate-agent`` and ``tunnelmate-peer`` processes to
it. Nothing here mocks the data path — the binaries under test are the ones that
ship.
"""

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

ROOT = Path(__file__).resolve().parents[1]
BUILD = Path(os.getenv("TUNNELMATE_BUILD_DIR", ROOT / "build"))
STREAM_BLOCK = 65536


# --------------------------------------------------------------------------
# deterministic payload generation (never touches disk)
# --------------------------------------------------------------------------


def deterministic_bytes(offset: int, length: int) -> bytes:
    """Return ``length`` bytes of the reproducible stream starting at ``offset``."""
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


# --------------------------------------------------------------------------
# port helpers
# --------------------------------------------------------------------------


def free_tcp_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def free_public_range(count: int = 2) -> int:
    """Find a base port where ``count`` consecutive TCP *and* UDP ports are free."""
    for _ in range(2000):
        base = random.randint(22000, 56000)
        held: list[socket.socket] = []
        try:
            for offset in range(count):
                tcp = socket.socket()
                udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                held.extend((tcp, udp))
                tcp.bind(("127.0.0.1", base + offset))
                udp.bind(("127.0.0.1", base + offset))
            return base
        except OSError:
            continue
        finally:
            for sock in held:
                sock.close()
    raise RuntimeError("no free public port range")


def port_is_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as sock:
        sock.settimeout(2)
        return sock.connect_ex((host, port)) == 0


def wait_for(predicate, timeout: float = 10.0, interval: float = 0.05) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise TimeoutError("condition did not become true")


def rss_kib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return 0
    return 0


def open_fds(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return 0


# --------------------------------------------------------------------------
# broker IPC
# --------------------------------------------------------------------------


def ipc_raw(path: Path, payload: str, timeout: float = 5.0) -> dict:
    """Send a raw line to the broker IPC socket and decode one JSON reply."""
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(timeout)
        sock.connect(str(path))
        sock.sendall(payload.encode() if isinstance(payload, str) else payload)
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data or b"{}")


def ipc(path: Path, op: str, **values) -> dict:
    response = ipc_raw(path, json.dumps({"op": op, **values}) + "\n")
    assert response.get("status") == "ok", response
    return response


def ipc_expect_error(path: Path, op: str, **values) -> dict:
    response = ipc_raw(path, json.dumps({"op": op, **values}) + "\n")
    assert response.get("status") != "ok", response
    return response


# --------------------------------------------------------------------------
# local test services
# --------------------------------------------------------------------------


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class HashSinkHandler(socketserver.BaseRequestHandler):
    """Consume a stream, verify it against the generator, and report the digest."""

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
                        i
                        for i, pair in enumerate(zip(data, wanted, strict=True))
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


def threaded_tcp_server(handler) -> socketserver.ThreadingTCPServer:
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class UdpEcho(threading.Thread):
    """UDP echo service that records what it saw, one datagram at a time."""

    def __init__(self, transform=None) -> None:
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.stop_event = threading.Event()
        self.sizes: list[int] = []
        self.sources: set[tuple[str, int]] = set()
        self.count = 0
        self.transform = transform

    def run(self) -> None:
        self.sock.settimeout(0.1)
        while not self.stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                return
            self.count += 1
            self.sizes.append(len(data))
            self.sources.add(addr)
            reply = self.transform(data) if self.transform else data
            if reply is not None:
                self.sock.sendto(reply, addr)

    def close(self) -> None:
        self.stop_event.set()
        self.join(timeout=2)
        self.sock.close()


# --------------------------------------------------------------------------
# broker / agent / peer process management
# --------------------------------------------------------------------------

SANITIZER_ENV = {
    "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:quarantine_size_mb=16",
    "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
}


def make_certificate(directory: Path, common_name: str = "localhost") -> tuple[Path, Path]:
    cert, key = directory / "broker.crt", directory / "broker.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", f"/CN={common_name}",
            "-addext", f"subjectAltName=DNS:{common_name},IP:127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert, key


class BrokerProcess:
    """A running broker plus every child process attached to it."""

    def __init__(self, tmp_path: Path, ports: int = 2, settings: dict | None = None):
        self.tmp = tmp_path
        self.control_port = free_tcp_port()
        self.public_start = free_public_range(ports)
        self.public_end = self.public_start + ports - 1
        self.cert, self.key = make_certificate(tmp_path)
        self.socket_path = tmp_path / "broker.sock"
        self.conf_path = tmp_path / "broker.conf"
        self.log_path = tmp_path / "broker.log"
        self.env = {**os.environ, **SANITIZER_ENV}
        self.processes: list[subprocess.Popen] = []
        self.settings = {
            "broker.listen_host": "127.0.0.1",
            "broker.control_port": self.control_port,
            "broker.public_port_start": self.public_start,
            "broker.public_port_end": self.public_end,
            "broker.tls_cert": self.cert,
            "broker.tls_key": self.key,
            "broker.hmac_key_file": tmp_path / "hmac.key",
            "broker.broker_socket": self.socket_path,
            "broker.log_level": "debug",
            "broker.shutdown_grace_ms": 50,
            **(settings or {}),
        }
        self._log = None
        self.process: subprocess.Popen | None = None

    def write_config(self) -> None:
        self.conf_path.write_text(
            "".join(f"{key} = {value}\n" for key, value in self.settings.items())
        )

    def start(self) -> None:
        self.write_config()
        self._log = self.log_path.open("ab")
        self.process = subprocess.Popen(
            [str(BUILD / "broker" / "tunnelmated"), "-c", str(self.conf_path)],
            stdout=subprocess.DEVNULL,
            stderr=self._log,
            env=self.env,
        )
        wait_for(
            lambda: self.socket_path.exists() or self.process.poll() is not None,
            timeout=15,
        )
        if self.process.poll() is not None:
            pytest.fail(f"broker exited: {self.log_text()}")

    def log_text(self) -> str:
        try:
            return self.log_path.read_text(errors="replace")
        except FileNotFoundError:
            return ""

    def stop(self, signal_kill: bool = False, timeout: float = 5.0) -> int | None:
        if self.process is None or self.process.poll() is not None:
            return self.process.returncode if self.process else None
        if signal_kill:
            self.process.kill()
        else:
            self.process.terminate()
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        return self.process.returncode

    def restart(self) -> None:
        """Stop and start the broker, keeping the same ports and certificate."""
        self.stop()
        self.socket_path.unlink(missing_ok=True)
        self.start()

    # -- helpers -----------------------------------------------------------

    def ipc(self, op: str, **values) -> dict:
        return ipc(self.socket_path, op, **values)

    def create_tunnel(self, tunnel_id: str, proto: str = "tcp", closed: bool = False) -> dict:
        return self.ipc("create_tunnel", tunnel_id=tunnel_id, proto=proto, closed=closed)

    def status(self) -> dict:
        """Broker-wide counters (the ``now`` object of the IPC status reply)."""
        return self.ipc("get_status")["now"]

    def tunnels(self) -> list[dict]:
        return self.ipc("get_tunnels")["tunnels"]

    def tunnel(self, tunnel_id: str) -> dict | None:
        for entry in self.tunnels():
            if entry.get("id") == tunnel_id:
                return entry
        return None

    def agent_online(self, tunnel_id: str) -> bool:
        entry = self.tunnel(tunnel_id)
        return bool(entry and entry.get("agent_online"))

    def track(self, process: subprocess.Popen) -> subprocess.Popen:
        self.processes.append(process)
        return process

    def cleanup(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        self.stop()
        if self._log is not None:
            self._log.close()


def start_agent(
    broker: BrokerProcess,
    tunnel: dict,
    local_port: int,
    protocol: str = "tcp",
    name: str | None = None,
    wait_online: bool = True,
    extra: dict | None = None,
) -> subprocess.Popen:
    label = name or f"{tunnel['tunnel_id']}-{protocol}"
    conf = broker.tmp / f"agent-{label}.conf"
    settings = {
        "agent.tunnel_id": tunnel["tunnel_id"],
        "agent.agent_secret": tunnel["agent_secret"],
        "agent.local_host": "127.0.0.1",
        "agent.local_port": local_port,
        "agent.broker_host": "127.0.0.1",
        "agent.broker_port": broker.control_port,
        "agent.broker_udp_port": tunnel.get("public_port", 0),
        "agent.protocol": protocol,
        "agent.verify_ca": "false",
        "agent.log_level": "debug",
        **(extra or {}),
    }
    conf.write_text("".join(f"{key} = {value}\n" for key, value in settings.items()))
    conf.chmod(0o600)
    log_path = broker.tmp / f"agent-{label}.log"
    log = log_path.open("ab")
    process = subprocess.Popen(
        [str(BUILD / "agent" / "tunnelmate-agent"), "-c", str(conf)],
        stdout=subprocess.DEVNULL,
        stderr=log,
        env=broker.env,
    )
    process._tm_log_path = log_path  # type: ignore[attr-defined]
    broker.track(process)
    if wait_online:
        wait_for(
            lambda: process.poll() is not None or broker.agent_online(tunnel["tunnel_id"]),
            timeout=20,
        )
        assert process.poll() is None, log_path.read_text(errors="replace")
    return process


def start_peer(
    broker: BrokerProcess,
    tunnel: dict,
    token: str,
    local_port: int,
    protocol: str = "tcp",
    wait_ready: bool = True,
) -> subprocess.Popen:
    token_file = broker.tmp / f"peer-{protocol}-{local_port}.token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    remote_port = tunnel["public_port"] if protocol == "udp" else broker.control_port
    log_path = broker.tmp / f"peer-{protocol}-{local_port}.log"
    log = log_path.open("ab")
    process = subprocess.Popen(
        [
            str(BUILD / "peer" / "tunnelmate-peer"),
            "connect",
            f"tunnel://127.0.0.1:{remote_port}/{tunnel['tunnel_id']}",
            "--token-file", str(token_file),
            "--listen", f"127.0.0.1:{local_port}",
            "--protocol", protocol,
            "--no-verify-ca",
            "--log-level", "debug",
        ],
        stdout=subprocess.DEVNULL,
        stderr=log,
        env=broker.env,
    )
    process._tm_log_path = log_path  # type: ignore[attr-defined]
    broker.track(process)
    if wait_ready:
        if protocol == "tcp":
            wait_for(lambda: process.poll() is not None or port_is_open(local_port), timeout=10)
        else:
            wait_for(
                lambda: (
                    process.poll() is not None
                    or "udp_authed" in log_path.read_text(errors="replace")
                ),
                timeout=15,
            )
        assert process.poll() is None, log_path.read_text(errors="replace")
    return process


def binaries_present() -> bool:
    return all(
        (BUILD / part / name).exists()
        for part, name in (
            ("broker", "tunnelmated"),
            ("agent", "tunnelmate-agent"),
            ("peer", "tunnelmate-peer"),
        )
    )
