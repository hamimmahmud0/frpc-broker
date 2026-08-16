from __future__ import annotations

import hashlib
import hmac
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from tunnelmate_api.config import Settings
from tunnelmate_api.main import create_app
from tunnelmate_api.security import bootstrap_admin


class FakeBroker:
    def __init__(self) -> None:
        self.tunnels: dict[str, dict] = {}
        self.port = 24000

    @staticmethod
    def digest(value: str) -> str:
        return hmac.new(b"broker-key", value.encode(), hashlib.sha256).hexdigest()

    async def health(self) -> bool:
        return True

    async def call(self, op: str, **params):
        if op == "health":
            return {"status": "ok"}
        if op in {"get_tunnels", "get_status"}:
            return {
                "status": "ok",
                "now": {"tunnel_count": len(self.tunnels), "stream_count": 0},
                "tunnels": list(self.tunnels.values()),
            }
        if op == "create_tunnel":
            tid = params["tunnel_id"]
            if tid in self.tunnels:
                raise RuntimeError("already exists")
            port = params.get("prefer_port") or self.port
            self.port += 1
            secret = "agent-secret-value-0123456789"
            token = params.get("shared_token") or "shared-token-value-0123456789"
            ah = params.get("agent_secret_hmac") or self.digest(secret)
            th = params.get("shared_token_hmac") or (self.digest(token) if params["closed"] else "")
            self.tunnels[tid] = {
                "id": tid,
                "proto": params["proto"],
                "closed": params["closed"],
                "public_port": port,
                "agent_online": False,
                "streams_active": 0,
            }
            result = {
                "status": "ok",
                "tunnel_id": tid,
                "public_port": port,
                "agent_secret_hmac": ah,
                "shared_token_hmac": th,
            }
            if "agent_secret_hmac" not in params:
                result["agent_secret"] = secret
                if params["closed"]:
                    result["shared_token"] = token
            return result
        if op == "delete_tunnel":
            self.tunnels.pop(params["tunnel_id"], None)
            return {"status": "ok"}
        if op in {"enable_tunnel", "disable_tunnel"}:
            return {"status": "ok"}
        if op.startswith("rotate_"):
            secret = "rotated-value-0123456789012345"
            return {"status": "ok", "secret": secret, "secret_hmac": self.digest(secret)}
        raise AssertionError(op)


def settings(root: Path) -> Settings:
    return Settings(
        db_path=root / "control.db",
        broker_socket=root / "broker.sock",
        public_host="broker.test",
        broker_control_port=7000,
        lease_seconds=86400,
        secret_key=b"test-secret-key-that-is-long-enough",
        production=False,
        docs_enabled=True,
        secure_cookies=False,
        create_rate_per_minute=20,
        max_tunnels_per_ip=20,
        max_request_bytes=65536,
        max_announcement_bytes=16384,
        max_attribute_depth=6,
        max_attribute_keys=128,
        admin_username=None,
        admin_password=None,
    )


def test_tunnel_lifecycle_and_registry() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(settings(Path(tmp)))
        app.state.broker = FakeBroker()
        with TestClient(app) as client:
            created = client.post("/v1/tunnels", json={"scope": "open", "protocol": "tcp"})
            assert created.status_code == 201
            body = created.json()
            assert body["peer_address"].startswith("tcp://broker.test:")
            assert body["agent_secret"] and body["management_secret"]
            tunnel_id = body["tunnel_id"]
            secret = body["management_secret"]

            assert client.get(f"/v1/tunnels/{tunnel_id}").status_code == 404
            status = client.get(
                f"/v1/tunnels/{tunnel_id}", headers={"X-Tunnel-Management-Secret": secret}
            )
            assert status.status_code == 200

            ann = client.post(
                "/v1/announce",
                headers={"X-Tunnel-Management-Secret": secret},
                json={
                    "tunnel_id": tunnel_id,
                    "service_name": "Yolo Inference Service",
                    "service_id": "yolov11-detection",
                    "llms": "https://example.test/llms.txt",
                    "attributes": {"version": 11, "size": "n"},
                },
            )
            assert ann.status_code == 201
            found = client.get("/v1/announce/search?service=yolo&attribute.size=n")
            assert found.status_code == 200
            assert found.json()["items"][0]["attributes"] == {"version": 11, "size": "n"}

            assert client.delete(f"/v1/tunnels/{tunnel_id}").status_code == 404
            deleted = client.delete(
                f"/v1/tunnels/{tunnel_id}", headers={"X-Tunnel-Management-Secret": secret}
            )
            assert deleted.status_code == 200


def test_closed_tunnel_and_admin_csrf() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(settings(Path(tmp)))
        app.state.broker = FakeBroker()
        app.state.db.initialize()
        bootstrap_admin(app.state.db, "operator", "correct horse battery staple")
        with TestClient(app) as client:
            created = client.post("/v1/tunnels", json={"scope": "closed", "protocol": "udp"})
            assert created.status_code == 201
            assert created.json()["shared_token"]
            assert created.json()["peer_address"].startswith("tunnel://")

            unauth = client.get("/v1/admin/tunnels")
            assert unauth.status_code == 401
            login = client.post(
                "/v1/admin/login",
                json={"username": "operator", "password": "correct horse battery staple"},
            )
            assert login.status_code == 200
            csrf = login.json()["csrf_token"]
            listed = client.get("/v1/admin/tunnels")
            assert listed.status_code == 200 and len(listed.json()["items"]) == 1
            tunnel_id = listed.json()["items"][0]["tunnel_id"]
            assert (
                client.patch(
                    f"/v1/admin/tunnels/{tunnel_id}",
                    headers={"X-CSRF-Token": csrf},
                    json={"enabled": False},
                ).status_code
                == 200
            )
            blocked = client.post(
                "/v1/admin/blocked-ips",
                headers={"X-CSRF-Token": csrf},
                json={"cidr": "192.0.2.7/24", "reason": "test"},
            )
            assert blocked.status_code == 200
            assert client.get("/v1/admin/blocked-ips").json()["items"][0]["cidr"] == "192.0.2.0/24"
            assert client.delete(f"/v1/admin/tunnels/{tunnel_id}").status_code == 403
            assert (
                client.delete(
                    f"/v1/admin/tunnels/{tunnel_id}", headers={"X-CSRF-Token": csrf}
                ).status_code
                == 200
            )


def test_validation_and_health() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(settings(Path(tmp)))
        app.state.broker = FakeBroker()
        with TestClient(app) as client:
            assert client.get("/health/live").status_code == 200
            assert client.get("/health/ready").status_code == 200
            bad = client.post("/v1/tunnels", json={"scope": "open", "protocol": "icmp"})
            assert bad.status_code == 422
            assert bad.json()["error"]["code"] == "VALIDATION_ERROR"
            assert client.get("/llms.txt").headers["content-type"].startswith("text/plain")
            oversized = client.post(
                "/v1/tunnels", content=b"x", headers={"Content-Length": "999999"}
            )
            assert oversized.status_code == 413
            assert oversized.json()["error"]["code"] == "REQUEST_TOO_LARGE"
