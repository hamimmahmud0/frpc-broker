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
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx

from .config import PeerConfig, TunnelConfig

MessageHandler = Callable[[str, bytes, Any], bytes | None]


class TunnelMateError(RuntimeError):
    pass


class _HandlerProxy:
    """Small opt-in TCP proxy used only when payload interception is requested."""

    def __init__(self, target_host: str, target_port: int, handler: MessageHandler):
        class RequestHandler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                upstream = socket.create_connection(
                    (target_host, target_port), timeout=10
                )
                upstream.settimeout(None)
                context = {
                    "peer": self.client_address,
                    "service": (target_host, target_port),
                }

                def relay(
                    source: socket.socket, destination: socket.socket, direction: str
                ) -> None:
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
                    target=relay, args=(peer, upstream, "peer_to_service"), daemon=True
                )
                second = threading.Thread(
                    target=relay, args=(upstream, peer, "service_to_peer"), daemon=True
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
            self._handler_proxy = _HandlerProxy(local_host, local_port, self._handler)
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
