"""Server-side behaviour of the admin console routes.

Browser automation is deliberately avoided: what matters is that the routes
authorise correctly, render escaped data, and return the shapes the small
vanilla-JS console expects.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "control"))
sys.path.insert(0, str(ROOT / "control" / "tests"))

pytest.importorskip("fastapi", reason="control-plane dependencies are not installed")

from test_api import FakeBroker, settings
from tunnelmate_api.main import create_app
from tunnelmate_api.metrics import (
    SystemMetrics,
    disk_info,
    memory_info,
    process_info,
)
from tunnelmate_api.security import bootstrap_admin

ADMIN_PASSWORD = "correct horse battery staple"


@pytest.fixture
def client():
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(settings(Path(tmp)))
        app.state.broker = FakeBroker()
        app.state.db.initialize()
        bootstrap_admin(app.state.db, "operator", ADMIN_PASSWORD)
        with TestClient(app) as test_client:
            yield test_client


def login(client: TestClient) -> str:
    response = client.post(
        "/v1/admin/login", json={"username": "operator", "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    return response.json()["csrf_token"]


def make_tunnel(client: TestClient, protocol: str = "tcp") -> dict:
    response = client.post("/v1/tunnels", json={"scope": "open", "protocol": protocol})
    assert response.status_code == 201
    return response.json()


# ---------------------------------------------------------------------------
# host metric collection
# ---------------------------------------------------------------------------


def test_host_readings_are_sane() -> None:
    """The /proc readers must return plausible numbers, not zeros or crashes."""
    memory = memory_info()
    assert memory["total_kib"] > 0
    assert 0 <= memory["used_percent"] <= 100

    disk = disk_info("/")
    assert disk["total_bytes"] > 0
    assert 0 <= disk["used_percent"] <= 100

    process = process_info()
    assert process["rss_kib"] > 0
    assert process["open_fds"] > 0


def test_series_is_bounded() -> None:
    """History is a ring: an always-on service must not grow a metrics list."""
    metrics = SystemMetrics(history=5)
    for index in range(50):
        metrics.collect({"rx_bytes_total": index * 1000, "tunnel_count": index})
    assert len(metrics.samples) == 5
    assert len(metrics.series()) == 5
    latest = metrics.latest()
    assert latest is not None
    assert latest["broker"]["tunnel_count"] == 49


def test_rates_are_derived_and_never_negative() -> None:
    """Counters reset when the broker restarts; a rate must not go negative."""
    metrics = SystemMetrics(history=10)
    metrics.collect({"rx_bytes_total": 1_000_000})
    metrics.collect({"rx_bytes_total": 2_000_000})
    assert metrics.latest()["rates"]["rx_bytes_total"] >= 0
    # Simulate a broker restart: the counter drops back to zero.
    metrics.collect({"rx_bytes_total": 0})
    assert metrics.latest()["rates"]["rx_bytes_total"] == 0


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------


def test_system_endpoint_requires_admin(client: TestClient) -> None:
    assert client.get("/v1/admin/system").status_code in {401, 403}
    assert client.get("/v1/admin/system/stream").status_code in {401, 403}


def test_system_endpoint_returns_current_and_series(client: TestClient) -> None:
    login(client)
    response = client.get("/v1/admin/system?history=10")
    assert response.status_code == 200
    body = response.json()
    assert body["current"] is not None
    assert isinstance(body["series"], list) and body["series"]
    current = body["current"]
    for key in ("cpu_percent", "memory", "disk", "api", "broker_process", "broker", "rates"):
        assert key in current, key
    assert current["memory"]["total_kib"] > 0
    assert body["interval_seconds"] >= 1


def test_system_stream_emits_server_sent_events(client: TestClient) -> None:
    """The console consumes this with EventSource, so the framing must be SSE."""
    login(client)
    # events=1 makes the stream terminate so the test cannot hang on it.
    response = client.get("/v1/admin/system/stream?events=1")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers.get("cache-control") == "no-store"
    frames = [line for line in response.text.splitlines() if line.startswith("data: ")]
    assert frames, f"stream produced no data frames: {response.text[:200]!r}"
    payload = json.loads(frames[0][6:])
    assert "cpu_percent" in payload
    assert "memory" in payload


def test_stream_inspection_reports_runtime_detail(client: TestClient) -> None:
    login(client)
    tunnel = make_tunnel(client, "udp")
    response = client.get(f"/v1/admin/tunnels/{tunnel['tunnel_id']}/streams")
    assert response.status_code == 200
    body = response.json()
    assert body["tunnel"]["tunnel_id"] == tunnel["tunnel_id"]
    assert body["protocol"] == "udp"
    assert body["streams_active"] == 0

    missing = client.get("/v1/admin/tunnels/tun_nope/streams")
    assert missing.status_code == 404


def test_stream_inspection_requires_admin(client: TestClient) -> None:
    tunnel = make_tunnel(client)
    response = client.get(f"/v1/admin/tunnels/{tunnel['tunnel_id']}/streams")
    assert response.status_code in {401, 403}


def test_kill_stream_requires_csrf(client: TestClient) -> None:
    csrf = login(client)
    tunnel = make_tunnel(client)
    path = f"/v1/admin/tunnels/{tunnel['tunnel_id']}/streams/1/kill"
    assert client.post(path).status_code == 403
    # With CSRF the request reaches the broker, which has no such stream.
    assert client.post(path, headers={"X-CSRF-Token": csrf}).status_code in {200, 404}


# ---------------------------------------------------------------------------
# rendered console
# ---------------------------------------------------------------------------


def test_admin_page_renders_tables_and_panels(client: TestClient) -> None:
    login(client)
    make_tunnel(client, "tcp")
    make_tunnel(client, "udp")
    page = client.get("/admin")
    assert page.status_code == 200
    body = page.text
    for marker in ("system-tiles", "id=\"tunnels\"", "id=\"announcements\"", "id=\"topology\"", "id=\"inspect\""):
        assert marker in body, marker
    assert "TCP" in body and "UDP" in body


def test_console_assets_are_self_hosted(client: TestClient) -> None:
    """CSP is default-src 'self', so no asset may come from a CDN."""
    login(client)
    body = client.get("/admin").text
    assert "http://" not in body.replace("http://127.0.0.1", "").replace("http://localhost", "")
    assert "cdn." not in body
    for asset in ("/static/admin.css", "/static/admin.js"):
        response = client.get(asset)
        assert response.status_code == 200, asset
        assert response.content


def test_topology_reports_protocol_and_counts(client: TestClient) -> None:
    login(client)
    tunnel = make_tunnel(client, "udp")
    client.post(
        "/v1/announce",
        headers={"X-Tunnel-Management-Secret": tunnel["management_secret"]},
        json={
            "tunnel_id": tunnel["tunnel_id"],
            "service_name": "Game Server",
            "service_id": "my-game",
            "llms": "https://example.test/llms.txt",
            "attributes": {"region": "asia"},
        },
    )
    response = client.get("/v1/admin/topology")
    assert response.status_code == 200
    body = response.json()
    entry = next(t for t in body["tunnels"] if t["id"] == tunnel["tunnel_id"])
    assert entry["proto"] == "udp"
    assert entry["announcements"][0]["service_name"] == "Game Server"


def test_admin_search_filters_tunnels(client: TestClient) -> None:
    login(client)
    wanted = make_tunnel(client, "tcp")
    make_tunnel(client, "udp")
    response = client.get(f"/v1/admin/tunnels?q={wanted['tunnel_id']}")
    assert response.status_code == 200
    items = response.json()["items"]
    assert [item["tunnel_id"] for item in items] == [wanted["tunnel_id"]]
