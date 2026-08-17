from __future__ import annotations

import atexit
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx

from .config import PeerConfig, TunnelConfig

MessageHandler = Callable[[str, bytes, "HandlerContext"], bytes | None]

PEER_TO_SERVICE = "peer_to_service"
SERVICE_TO_PEER = "service_to_peer"


class TunnelMateError(RuntimeError):
    pass


@dataclass(frozen=True)
class HandlerContext:
    """What a message handler is told about the chunk or datagram it is given.

    Deliberately carries no credential: a handler is user code and has no
    business seeing the tunnel's secrets.
    """

    remote_ip: str
    remote_port: int
    tunnel_id: str | None
    protocol: str
    direction: str
    flow_id: str | None = None

    @property
    def remote_address(self) -> str:
        return f"{self.remote_ip}:{self.remote_port}"


class _HandlerProxy:
    """Opt-in TCP proxy, used only when payload interception is requested.

    TCP has no message boundaries, so the handler sees arbitrary chunks; that
    limitation is the application's to reason about, not something the proxy can
    paper over.
    """

    def __init__(
        self,
        target_host: str,
        target_port: int,
        handler: MessageHandler,
        tunnel_id: str | None = None,
    ):
        class RequestHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                upstream = socket.create_connection(
                    (target_host, target_port), timeout=10
                )
                upstream.settimeout(None)
                remote_ip, remote_port = self.client_address[0], self.client_address[1]

                def relay(
                    source: socket.socket, destination: socket.socket, direction: str
                ) -> None:
                    context = HandlerContext(
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        tunnel_id=tunnel_id,
                        protocol="tcp",
                        direction=direction,
                    )
                    try:
                        while True:
                            chunk = source.recv(65536)
                            if not chunk:
                                try:
                                    destination.shutdown(socket.SHUT_WR)
                                except OSError:
                                    pass
                                return
                            transformed = handler(direction, chunk, context)
                            if transformed is not None:
                                if not isinstance(transformed, bytes):
                                    raise TypeError(
                                        "message handler must return bytes or None"
                                    )
                                destination.sendall(transformed)
                    except Exception:  # noqa: BLE001 - user handlers may raise anything
                        try:
                            destination.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

                peer = self.request
                first = threading.Thread(
                    target=relay, args=(peer, upstream, PEER_TO_SERVICE), daemon=True
                )
                second = threading.Thread(
                    target=relay, args=(upstream, peer, SERVICE_TO_PEER), daemon=True
                )
                try:
                    first.start()
                    second.start()
                    first.join()
                    second.join()
                finally:
                    upstream.close()

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), RequestHandler)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(
            target=self.server.serve_forever, name="tunnelmate-handler", daemon=True
        )

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class _UdpHandlerProxy:
    """Opt-in UDP proxy: exactly one handler call per datagram.

    Datagram boundaries are the whole point of a UDP tunnel, so this never
    coalesces: one datagram in gives one handler call, and returned bytes are
    sent as exactly one datagram. Returning None drops it. Each remote address
    gets its own upstream socket so the service's replies route back correctly,
    the same NAT-style mapping the C agent uses.
    """

    MAX_DATAGRAM = 65535

    def __init__(
        self,
        target_host: str,
        target_port: int,
        handler: MessageHandler,
        tunnel_id: str | None = None,
        max_flows: int = 1024,
    ):
        self._target = (target_host, target_port)
        self._handler = handler
        self._tunnel_id = tunnel_id
        self._max_flows = max_flows
        self._flows: dict[tuple[str, int], socket.socket] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = int(self.sock.getsockname()[1])
        self.thread = threading.Thread(
            target=self._serve, name="tunnelmate-udp-handler", daemon=True
        )

    def _context(self, remote: tuple[str, int], direction: str) -> HandlerContext:
        return HandlerContext(
            remote_ip=remote[0],
            remote_port=remote[1],
            tunnel_id=self._tunnel_id,
            protocol="udp",
            direction=direction,
            flow_id=f"uflow_{remote[0]}:{remote[1]}",
        )

    def _reply_pump(self, remote: tuple[str, int], upstream: socket.socket) -> None:
        while not self._stop.is_set():
            try:
                data, _ = upstream.recvfrom(self.MAX_DATAGRAM)
            except (TimeoutError, OSError):
                continue
            try:
                out = self._handler(SERVICE_TO_PEER, data, self._context(remote, SERVICE_TO_PEER))
            except Exception:  # noqa: BLE001,S112 - a bad handler drops its own datagram
                continue
            if out is None:
                continue
            if not isinstance(out, bytes):
                raise TypeError("message handler must return bytes or None")
            try:
                self.sock.sendto(out, remote)
            except OSError:
                return

    def _upstream_for(self, remote: tuple[str, int]) -> socket.socket | None:
        with self._lock:
            existing = self._flows.get(remote)
            if existing is not None:
                return existing
            if len(self._flows) >= self._max_flows:
                return None
            upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream.settimeout(0.5)
            upstream.connect(self._target)
            self._flows[remote] = upstream
        threading.Thread(
            target=self._reply_pump, args=(remote, upstream), daemon=True
        ).start()
        return upstream

    def _serve(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, remote = self.sock.recvfrom(self.MAX_DATAGRAM)
            except (TimeoutError, OSError):
                continue
            upstream = self._upstream_for(remote)
            if upstream is None:
                continue
            try:
                out = self._handler(PEER_TO_SERVICE, data, self._context(remote, PEER_TO_SERVICE))
            except Exception:  # noqa: BLE001,S112 - a bad handler drops its own datagram
                continue
            if out is None:
                continue
            if not isinstance(out, bytes):
                raise TypeError("message handler must return bytes or None")
            try:
                upstream.send(out)
            except OSError:
                continue

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self._stop.set()
        self.thread.join(timeout=2)
        with self._lock:
            for upstream in self._flows.values():
                upstream.close()
            self._flows.clear()
        self.sock.close()


def _binary(explicit: Path | None, env_name: str, name: str) -> str:
    if explicit:
        return str(explicit)
    if os.getenv(env_name):
        return os.environ[env_name]
    found = shutil.which(name)
    if not found:
        raise TunnelMateError(f"{name} was not found; set {env_name}")
    return found


def _write_protected(directory: Path, name: str, content: str) -> Path:
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(content)
    return path


class Tunnel:
    def __init__(self, broker_url: str, config: TunnelConfig, timeout: float = 10.0):
        self.broker_url = broker_url.rstrip("/")
        self.config = config
        self._http = httpx.Client(base_url=self.broker_url, timeout=timeout)
        self._created: dict[str, Any] | None = None
        self._announcement: dict[str, Any] | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        self._renew_stop = threading.Event()
        self._renew_thread: threading.Thread | None = None
        self._handler: MessageHandler | None = None
        self._handler_proxy: _HandlerProxy | None = None
        self._closed = False
        atexit.register(self.stop)

    @property
    def tunnel_id(self) -> str | None:
        return self._created and self._created["tunnel_id"]

    @property
    def peer_address(self) -> str | None:
        return self._created and self._created["peer_address"]

    @property
    def management_secret(self) -> str | None:
        return self._created and self._created["management_secret"]

    @property
    def shared_token(self) -> str | None:
        return self._created and self._created.get("shared_token")

    def _raise(self, response: httpx.Response) -> None:
        if response.is_success:
            return
        try:
            error = response.json().get("error", {})
            message = error.get("message", response.text)
            code = error.get("code", f"HTTP_{response.status_code}")
        except (ValueError, AttributeError, TypeError):
            code, message = f"HTTP_{response.status_code}", response.text
        raise TunnelMateError(f"{code}: {message}")

    def _ensure_created(self) -> dict[str, Any]:
        if self._created:
            return self._created
        payload: dict[str, Any] = {
            "scope": self.config.scope,
            "protocol": self.config.protocol,
        }
        if self.config.shared_token:
            payload["shared_token"] = self.config.shared_token
        response = self._http.post("/v1/tunnels", json=payload)
        self._raise(response)
        self._created = response.json()
        return self._created

    def _headers(self) -> dict[str, str]:
        created = self._ensure_created()
        return {"X-Tunnel-Management-Secret": created["management_secret"]}

    def announce(self) -> dict[str, Any]:
        created = self._ensure_created()
        missing = [
            key
            for key in ("service_name", "service_id", "llms")
            if not getattr(self.config, key)
        ]
        if missing:
            raise TunnelMateError("announcement requires " + ", ".join(missing))
        if self._announcement:
            return self._announcement
        response = self._http.post(
            "/v1/announce",
            headers=self._headers(),
            json={
                "tunnel_id": created["tunnel_id"],
                "service_name": self.config.service_name,
                "service_id": self.config.service_id,
                "llms": self.config.llms,
                "attributes": self.config.attributes,
            },
        )
        self._raise(response)
        self._announcement = response.json()
        return self._announcement

    def set_message_handler(self, handler: MessageHandler | None) -> None:
        if self._process:
            raise TunnelMateError("set the message handler before start()")
        self._handler = handler

    def start(self) -> Tunnel:
        if self._process and self._process.poll() is None:
            return self
        if self._handler is not None and self.config.protocol != "tcp":
            raise TunnelMateError("message handlers are supported for TCP tunnels only")
        created = self._ensure_created()
        binary = _binary(
            self.config.agent_binary, "TUNNELMATE_AGENT_BINARY", "tunnelmate-agent"
        )
        self._tmp = tempfile.TemporaryDirectory(prefix="tunnelmate-agent-")
        directory = Path(self._tmp.name)
        control_port = int(created.get("broker_control_port", 7000))
        host = httpx.URL(self.broker_url).host
        if not host:
            raise TunnelMateError("broker_url must include a host")
        local_host = self.config.host
        local_port = self.config.port
        if self._handler is not None:
            # UDP needs the datagram-preserving proxy; a stream proxy would
            # merge datagrams and silently break the application.
            proxy_cls = (
                _UdpHandlerProxy if self.config.protocol == "udp" else _HandlerProxy
            )
            self._handler_proxy = proxy_cls(
                local_host, local_port, self._handler, created["tunnel_id"]
            )
            self._handler_proxy.start()
            local_host = "127.0.0.1"
            local_port = self._handler_proxy.port
        lines = [
            f"agent.tunnel_id = {created['tunnel_id']}",
            f"agent.agent_secret = {created['agent_secret']}",
            f"agent.local_host = {local_host}",
            f"agent.local_port = {local_port}",
            f"agent.broker_host = {host}",
            f"agent.broker_port = {control_port}",
            f"agent.broker_udp_port = {created['public_port']}",
            f"agent.protocol = {self.config.protocol}",
            f"agent.verify_ca = {'true' if self.config.verify_ca else 'false'}",
            f"agent.log_level = {self.config.log_level}",
        ]
        if self.config.ca_path:
            lines.append(f"agent.ca_path = {self.config.ca_path}")
        conf = _write_protected(directory, "agent.conf", "\n".join(lines) + "\n")
        self._process = subprocess.Popen(
            [binary, "-c", str(conf)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None,
            close_fds=True,
            start_new_session=True,
        )
        time.sleep(0.05)
        if self._process.poll() is not None:
            code = self._process.returncode
            self._cleanup_process()
            raise TunnelMateError(f"tunnelmate-agent exited with status {code}")
        self._start_renewal()
        return self

    def _start_renewal(self) -> None:
        if self._renew_thread and self._renew_thread.is_alive():
            return
        self._renew_stop.clear()

        def loop() -> None:
            while not self._renew_stop.wait(6 * 3600):
                try:
                    self.renew()
                except (TunnelMateError, httpx.HTTPError):
                    continue

        self._renew_thread = threading.Thread(
            target=loop, name="tunnelmate-renew", daemon=True
        )
        self._renew_thread.start()

    def _cleanup_process(self) -> None:
        self._process = None
        if self._handler_proxy:
            self._handler_proxy.close()
            self._handler_proxy = None
        if self._tmp:
            self._tmp.cleanup()
            self._tmp = None

    def stop(self) -> None:
        self._renew_stop.set()
        process = self._process
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
        self._cleanup_process()

    def wait(self, timeout: float | None = None) -> int:
        if not self._process:
            raise TunnelMateError("tunnel is not started")
        return self._process.wait(timeout=timeout)

    def status(self) -> dict[str, Any]:
        created = self._ensure_created()
        response = self._http.get(
            f"/v1/tunnels/{created['tunnel_id']}", headers=self._headers()
        )
        self._raise(response)
        return response.json()

    def stats(self) -> dict[str, Any]:
        return self.status()

    def renew(self) -> dict[str, Any]:
        created = self._ensure_created()
        response = self._http.post(
            f"/v1/tunnels/{created['tunnel_id']}/renew", headers=self._headers()
        )
        self._raise(response)
        return response.json()

    def rotate_token(self) -> str:
        created = self._ensure_created()
        response = self._http.post(
            f"/v1/tunnels/{created['tunnel_id']}/rotate-token", headers=self._headers()
        )
        self._raise(response)
        token = response.json()["shared_token"]
        created["shared_token"] = token
        return token

    def unannounce(self) -> None:
        if not self._announcement:
            return
        response = self._http.delete(
            f"/v1/announce/{self._announcement['announcement_id']}",
            headers=self._headers(),
        )
        self._raise(response)
        self._announcement = None

    def delete(self) -> None:
        self.stop()
        if not self._created:
            return
        response = self._http.delete(
            f"/v1/tunnels/{self._created['tunnel_id']}", headers=self._headers()
        )
        self._raise(response)
        self._created = None
        self._announcement = None

    def close(self) -> None:
        if self._closed:
            return
        self.stop()
        self._http.close()
        self._closed = True

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class Peer:
    def __init__(self, config: PeerConfig):
        self.config = config
        self._process: subprocess.Popen[bytes] | None = None
        self._tmp: tempfile.TemporaryDirectory[str] | None = None
        atexit.register(self.stop)

    def start(self) -> Peer:
        if self._process and self._process.poll() is None:
            return self
        binary = _binary(
            self.config.peer_binary, "TUNNELMATE_PEER_BINARY", "tunnelmate-peer"
        )
        self._tmp = tempfile.TemporaryDirectory(prefix="tunnelmate-peer-")
        directory = Path(self._tmp.name)
        token = _write_protected(directory, "token", self.config.token + "\n")
        args = [
            binary,
            "connect",
            self.config.peer_address,
            "--token-file",
            str(token),
            "--listen",
            f"{self.config.local_host}:{self.config.local_port}",
            "--protocol",
            self.config.protocol,
            "--log-level",
            self.config.log_level,
        ]
        if self.config.ca_path:
            args.extend(["--ca", str(self.config.ca_path)])
        if not self.config.verify_ca:
            args.append("--no-verify-ca")
        self._process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None,
            close_fds=True,
            start_new_session=True,
        )
        time.sleep(0.05)
        if self._process.poll() is not None:
            code = self._process.returncode
            self.stop()
            raise TunnelMateError(f"tunnelmate-peer exited with status {code}")
        return self

    def stop(self) -> None:
        if self._process and self._process.poll() is None:
            try:
                os.killpg(self._process.pid, signal.SIGTERM)
                self._process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if self._process.poll() is None:
                    os.killpg(self._process.pid, signal.SIGKILL)
        self._process = None
        if self._tmp:
            self._tmp.cleanup()
            self._tmp = None

    def wait(self, timeout: float | None = None) -> int:
        if not self._process:
            raise TunnelMateError("peer is not started")
        return self._process.wait(timeout=timeout)

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *args: object) -> None:
        self.stop()
