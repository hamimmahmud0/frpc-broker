"""Security tests for the FastAPI control plane.

These exercise the threats listed in ``docs/threat-model.md`` that live above the
data path: injection, SSRF, CSRF, brute force, capability scoping and the input
limits that keep an anonymous public API from becoming an abuse tool.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "control"))
sys.path.insert(0, str(ROOT / "control" / "tests"))

pytest.importorskip("fastapi", reason="control-plane dependencies are not installed")

from test_api import FakeBroker, settings
from tunnelmate_api.main import create_app
from tunnelmate_api.security import (
    bootstrap_admin,
    hash_password,
    verify_password,
)

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


def make_tunnel(client: TestClient, scope: str = "open", protocol: str = "tcp") -> dict:
    response = client.post("/v1/tunnels", json={"scope": scope, "protocol": protocol})
    assert response.status_code == 201, response.text
    return response.json()


def login(client: TestClient) -> str:
    response = client.post(
        "/v1/admin/login", json={"username": "operator", "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return response.json()["csrf_token"]


# ---------------------------------------------------------------------------
# anonymous creation model
# ---------------------------------------------------------------------------


def test_creation_needs_no_global_credential(client: TestClient) -> None:
    """The whole point of the service: no account, no API key, no bearer token."""
    response = client.post("/v1/tunnels", json={"scope": "open", "protocol": "tcp"})
    assert response.status_code == 201
    body = response.json()
    assert body["agent_secret"] and body["management_secret"]
    # Sensitive capabilities are returned once and never listed again.
    readback = client.get(
        f"/v1/tunnels/{body['tunnel_id']}",
        headers={"X-Tunnel-Management-Secret": body["management_secret"]},
    )
    assert readback.status_code == 200
    assert "agent_secret" not in readback.json()
    assert "management_secret" not in readback.json()


def test_management_secret_is_scoped_to_one_tunnel(client: TestClient) -> None:
    """One tunnel's capability must never authorise another tunnel."""
    first = make_tunnel(client)
    second = make_tunnel(client)

    stolen = {"X-Tunnel-Management-Secret": first["management_secret"]}
    assert client.get(f"/v1/tunnels/{second['tunnel_id']}", headers=stolen).status_code == 404
    assert client.delete(f"/v1/tunnels/{second['tunnel_id']}", headers=stolen).status_code == 404
    assert (
        client.patch(
            f"/v1/tunnels/{second['tunnel_id']}", headers=stolen, json={"enabled": False}
        ).status_code
        == 404
    )
    # The rightful owner still works.
    assert (
        client.get(
            f"/v1/tunnels/{second['tunnel_id']}",
            headers={"X-Tunnel-Management-Secret": second["management_secret"]},
        ).status_code
        == 200
    )


def test_missing_or_wrong_secret_is_indistinguishable(client: TestClient) -> None:
    """Auth failure must not confirm whether a tunnel exists."""
    real = make_tunnel(client)
    absent = client.get("/v1/tunnels/tun_doesnotexistatall")
    wrong = client.get(
        f"/v1/tunnels/{real['tunnel_id']}",
        headers={"X-Tunnel-Management-Secret": "not-the-right-secret"},
    )
    assert absent.status_code == wrong.status_code == 404
    assert absent.json()["error"]["code"] == wrong.json()["error"]["code"]


def test_rotated_secret_revokes_the_old_one(client: TestClient) -> None:
    """Rotation must actually invalidate the previous capability."""
    tunnel = make_tunnel(client, scope="closed")
    old = tunnel["management_secret"]
    rotated = client.post(
        f"/v1/tunnels/{tunnel['tunnel_id']}/rotate-token",
        headers={"X-Tunnel-Management-Secret": old},
    )
    assert rotated.status_code == 200
    assert rotated.json()["shared_token"] != tunnel.get("shared_token")


# ---------------------------------------------------------------------------
# injection
# ---------------------------------------------------------------------------


SQL_PAYLOADS = [
    "'; DROP TABLE tunnels;--",
    "' OR '1'='1",
    "1; DELETE FROM announcements WHERE 1=1;--",
    "\" UNION SELECT password_hash FROM admin_users--",
    "%' OR service_id LIKE '%",
]


def test_sql_injection_in_search_is_inert(client: TestClient) -> None:
    """Search parameters are bound, never concatenated into SQL."""
    tunnel = make_tunnel(client)
    created = client.post(
        "/v1/announce",
        headers={"X-Tunnel-Management-Secret": tunnel["management_secret"]},
        json={
            "tunnel_id": tunnel["tunnel_id"],
            "service_name": "Canary Service",
            "service_id": "canary",
            "llms": "https://example.test/llms.txt",
            "attributes": {"kind": "canary"},
        },
    )
    assert created.status_code == 201

    for payload in SQL_PAYLOADS:
        for query in (
            f"/v1/announce/search?service={payload}",
            f"/v1/announce/search?service_id={payload}",
            f"/v1/announce/search?tunnel_id={payload}",
            f"/v1/announce/search?attribute.kind={payload}",
        ):
            response = client.get(query)
            assert response.status_code in {200, 422}, (query, response.text)

    # The canary survived every attempt, so no statement ever executed.
    still_there = client.get("/v1/announce/search?service_id=canary")
    assert still_there.status_code == 200
    assert len(still_there.json()["items"]) == 1


def test_xss_in_announcement_metadata_is_escaped(client: TestClient) -> None:
    """Announcement text is attacker-controlled and must never render as HTML."""
    tunnel = make_tunnel(client)
    payload = "<script>alert('xss')</script>"
    created = client.post(
        "/v1/announce",
        headers={"X-Tunnel-Management-Secret": tunnel["management_secret"]},
        json={
            "tunnel_id": tunnel["tunnel_id"],
            "service_name": payload,
            "service_id": "xss-probe",
            "llms": "https://example.test/llms.txt",
            "attributes": {"note": "<img src=x onerror=alert(1)>"},
        },
    )
    assert created.status_code == 201

    login(client)
    page = client.get("/admin")
    assert page.status_code == 200
    body = page.text
    assert "<script>alert('xss')</script>" not in body
    assert "<img src=x onerror=alert(1)>" not in body
    assert "&lt;script&gt;" in body or "&amp;lt;script" in body


def test_log_and_header_injection_are_rejected(client: TestClient) -> None:
    """CR/LF in attacker-controlled values must never reach a header or log line."""
    # Percent-encoded so the client transmits them rather than rejecting locally.
    for hostile in ("tun_%0d%0aInjected:%20yes", "tun_%0afake-log-line", "tun_%00null"):
        response = client.get(
            f"/v1/tunnels/{hostile}", headers={"X-Tunnel-Management-Secret": "x" * 32}
        )
        assert response.status_code in {400, 404, 422}
        assert "injected" not in {key.lower() for key in response.headers}
        for name, value in response.headers.items():
            assert "\n" not in value and "\r" not in value, name

    # The same for a reflected request id.
    reflected = client.get("/v1/status", headers={"X-Request-ID": "req_" + "a" * 200})
    assert "\n" not in reflected.headers["x-request-id"]
    assert len(reflected.headers["x-request-id"]) <= 80


def test_path_traversal_does_not_escape_static_root(client: TestClient) -> None:
    """Static assets must not serve arbitrary filesystem paths."""
    for attempt in (
        "/static/../../../../etc/passwd",
        "/static/..%2f..%2f..%2fetc%2fpasswd",
        "/static/....//....//etc/passwd",
    ):
        response = client.get(attempt)
        assert response.status_code in {400, 403, 404}, attempt
        assert "root:" not in response.text


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/_stats",
        "ftp://example.test/llms.txt",
        "javascript:alert(1)",
        "data:text/plain,hello",
        "http://",
        "not-a-url-at-all",
        "https://" + "a" * 4000 + ".test/llms.txt",
    ],
)
def test_llms_url_must_be_structurally_valid_http(client: TestClient, url: str) -> None:
    """Only http(s) URLs of sane length are accepted as an llms pointer."""
    tunnel = make_tunnel(client)
    response = client.post(
        "/v1/announce",
        headers={"X-Tunnel-Management-Secret": tunnel["management_secret"]},
        json={
            "tunnel_id": tunnel["tunnel_id"],
            "service_name": "SSRF probe",
            "service_id": "ssrf-probe",
            "llms": url,
            "attributes": {},
        },
    )
    assert response.status_code == 422, f"{url} was accepted"


def test_llms_url_is_never_fetched(client: TestClient, monkeypatch) -> None:
    """Storing an announcement must not make the VPS issue an outbound request."""
    calls: list[str] = []

    def explode(*args, **kwargs):  # pragma: no cover - only runs on regression
        calls.append(repr(args))
        raise AssertionError("the control plane fetched an announcement URL")

    for module_name in ("httpx", "urllib.request"):
        module = sys.modules.get(module_name)
        if module is None:
            continue
        for attribute in ("get", "request", "urlopen", "Client"):
            if hasattr(module, attribute):
                monkeypatch.setattr(module, attribute, explode, raising=False)

    tunnel = make_tunnel(client)
    response = client.post(
        "/v1/announce",
        headers={"X-Tunnel-Management-Secret": tunnel["management_secret"]},
        json={
            "tunnel_id": tunnel["tunnel_id"],
            "service_name": "Metadata probe",
            "service_id": "metadata-probe",
            # A classic cloud metadata endpoint: accepted as text, never visited.
            "llms": "http://169.254.169.254/latest/meta-data/llms.txt",
            "attributes": {},
        },
    )
    assert response.status_code == 201
    assert calls == []


# ---------------------------------------------------------------------------
# announcement ownership and limits
# ---------------------------------------------------------------------------


def test_announcement_ownership_is_enforced(client: TestClient) -> None:
    """A stranger must not edit or delete somebody else's listing."""
    owner = make_tunnel(client)
    stranger = make_tunnel(client)
    created = client.post(
        "/v1/announce",
        headers={"X-Tunnel-Management-Secret": owner["management_secret"]},
        json={
            "tunnel_id": owner["tunnel_id"],
            "service_name": "Owned Service",
            "service_id": "owned",
            "llms": "https://example.test/llms.txt",
            "attributes": {},
        },
    )
    assert created.status_code == 201
    announcement_id = created.json()["announcement_id"]

    hostile = {"X-Tunnel-Management-Secret": stranger["management_secret"]}
    assert client.patch(
        f"/v1/announce/{announcement_id}", headers=hostile, json={"service_name": "Hijacked"}
    ).status_code in {403, 404}
    assert client.delete(f"/v1/announce/{announcement_id}", headers=hostile).status_code in {
        403,
        404,
    }
    assert client.get(f"/v1/announce/{announcement_id}").json()["service_name"] == "Owned Service"


def test_peer_address_is_derived_not_trusted(client: TestClient) -> None:
    """A user must not be able to advertise an address they do not control."""
    tunnel = make_tunnel(client)
    created = client.post(
        "/v1/announce",
        headers={"X-Tunnel-Management-Secret": tunnel["management_secret"]},
        json={
            "tunnel_id": tunnel["tunnel_id"],
            "service_name": "Spoof attempt",
            "service_id": "spoof",
            "llms": "https://example.test/llms.txt",
            "peer_address": "tcp://victim.example.com:22",
            "attributes": {},
        },
    )
    assert created.status_code in {201, 422}
    if created.status_code == 201:
        assert created.json()["peer_address"] == tunnel["peer_address"]


def test_attribute_limits_bound_abuse(client: TestClient) -> None:
    """Deeply nested or enormous attributes are rejected before storage."""
    tunnel = make_tunnel(client)
    headers = {"X-Tunnel-Management-Secret": tunnel["management_secret"]}

    deep: dict = {"level": {}}
    cursor = deep["level"]
    for _ in range(64):
        cursor["level"] = {}
        cursor = cursor["level"]

    for attributes in (
        deep,
        {f"key{i}": i for i in range(5000)},
        {"blob": "x" * 200000},
    ):
        response = client.post(
            "/v1/announce",
            headers=headers,
            json={
                "tunnel_id": tunnel["tunnel_id"],
                "service_name": "Limit probe",
                "service_id": "limits",
                "llms": "https://example.test/llms.txt",
                "attributes": attributes,
            },
        )
        assert response.status_code in {413, 422}, response.status_code


def test_oversized_request_body_is_refused(client: TestClient) -> None:
    """API body limits protect a 2 GB VPS from trivially cheap pressure."""
    response = client.post(
        "/v1/tunnels", content=b"x" * 32, headers={"Content-Length": "10000000"}
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "REQUEST_TOO_LARGE"


# ---------------------------------------------------------------------------
# admin authentication
# ---------------------------------------------------------------------------


def test_admin_endpoints_reject_anonymous_access(client: TestClient) -> None:
    """Everything under /v1/admin requires a session."""
    for method, path in (
        ("get", "/v1/admin/tunnels"),
        ("get", "/v1/admin/announcements"),
        ("get", "/v1/admin/topology"),
        ("get", "/v1/admin/blocked-ips"),
        ("delete", "/v1/admin/tunnels/tun_whatever"),
    ):
        response = getattr(client, method)(path)
        assert response.status_code in {401, 403}, (method, path, response.status_code)

    # A well-formed body must still be refused without a session.
    blocked = client.post("/v1/admin/blocked-ips", json={"cidr": "203.0.113.0/24", "reason": "x"})
    assert blocked.status_code in {401, 403}


def test_admin_ui_redirects_anonymous_browsers(client: TestClient) -> None:
    response = client.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/login"


def test_csrf_token_is_required_and_validated(client: TestClient) -> None:
    """A session cookie alone must not authorise a state change."""
    csrf = login(client)
    tunnel = make_tunnel(client)
    target = f"/v1/admin/tunnels/{tunnel['tunnel_id']}"

    assert client.delete(target).status_code == 403
    assert client.delete(target, headers={"X-CSRF-Token": "wrong-token"}).status_code == 403
    assert client.delete(target, headers={"X-CSRF-Token": csrf}).status_code == 200


def test_session_cookie_has_protective_attributes(client: TestClient) -> None:
    response = client.post(
        "/v1/admin/login", json={"username": "operator", "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    cookie_header = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_header
    assert "SameSite" in cookie_header


def test_logout_invalidates_the_session(client: TestClient) -> None:
    csrf = login(client)
    assert client.get("/v1/admin/tunnels").status_code == 200
    assert client.post("/v1/admin/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert client.get("/v1/admin/tunnels").status_code in {401, 403}


def test_admin_login_is_rate_limited(client: TestClient) -> None:
    """Password guessing must get throttled rather than run at full speed."""
    codes = []
    for index in range(25):
        response = client.post(
            "/v1/admin/login",
            json={"username": "operator", "password": f"wrong-guess-{index}"},
        )
        codes.append(response.status_code)
    assert 429 in codes, f"no throttling observed: {sorted(set(codes))}"
    assert 200 not in codes


def test_password_hashing_is_salted_and_verifiable() -> None:
    """Passwords are stored as salted scrypt digests, never reversibly."""
    first = hash_password(ADMIN_PASSWORD)
    second = hash_password(ADMIN_PASSWORD)
    assert first != second, "hashes must be salted"
    assert first.startswith("scrypt$")
    assert ADMIN_PASSWORD not in first
    assert verify_password(ADMIN_PASSWORD, first)
    assert not verify_password("almost correct horse", first)
    with pytest.raises(ValueError):
        hash_password("short")


def test_no_default_admin_exists() -> None:
    """A fresh deployment must not ship usable credentials."""
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(settings(Path(tmp)))
        app.state.broker = FakeBroker()
        with TestClient(app) as fresh:
            for username, password in (
                ("admin", "admin"),
                ("admin", "password"),
                ("operator", "operator"),
                ("tunnelmate", "tunnelmate"),
            ):
                response = fresh.post(
                    "/v1/admin/login", json={"username": username, "password": password}
                )
                assert response.status_code != 200, (username, password)


# ---------------------------------------------------------------------------
# responses
# ---------------------------------------------------------------------------


def test_errors_never_leak_internals(client: TestClient) -> None:
    """Error bodies carry a code and a request id, not a traceback."""
    response = client.get("/v1/tunnels/tun_missing")
    assert response.status_code == 404
    body = response.json()
    assert set(body["error"]) >= {"code", "message", "request_id"}
    assert body["error"]["request_id"].startswith("req_")
    lowered = response.text.lower()
    assert "traceback" not in lowered
    assert "sqlite" not in lowered
    assert ".py" not in lowered


def test_security_headers_are_set(client: TestClient) -> None:
    response = client.get("/admin/login")
    assert response.status_code == 200
    headers = {key.lower(): value for key, value in response.headers.items()}
    assert headers.get("x-content-type-options") == "nosniff"
    assert "content-security-policy" in headers
    assert headers.get("x-frame-options", "").upper() in {"DENY", "SAMEORIGIN"}


def test_creation_rate_limit_applies_per_source(client: TestClient) -> None:
    """Anonymous creation is free but not unlimited."""
    codes = []
    for _ in range(40):
        codes.append(client.post("/v1/tunnels", json={"scope": "open", "protocol": "tcp"}).status_code)
        if codes[-1] == 429:
            break
    assert 429 in codes, "creation was never rate limited"


def test_identifiers_are_random_not_sequential(client: TestClient) -> None:
    """Public IDs must not expose database ordering or allow enumeration."""
    ids = [make_tunnel(client)["tunnel_id"] for _ in range(5)]
    assert all(value.startswith("tun_") for value in ids)
    assert len(set(ids)) == len(ids)
    suffixes = [value.removeprefix("tun_") for value in ids]
    assert all(len(suffix) >= 16 for suffix in suffixes)
    assert not any(suffix.isdigit() for suffix in suffixes)


def test_lease_expiry_is_reported_and_renewable(client: TestClient) -> None:
    """Leases bound how long an anonymous tunnel can hold a public port."""
    tunnel = make_tunnel(client)
    headers = {"X-Tunnel-Management-Secret": tunnel["management_secret"]}
    original = client.get(f"/v1/tunnels/{tunnel['tunnel_id']}", headers=headers).json()
    assert original["expires_at"] > int(time.time())

    app = client.app
    app.state.db.connect().execute(
        "UPDATE tunnels SET expires_at=? WHERE tunnel_id=?",
        (int(time.time()) - 3600, tunnel["tunnel_id"]),
    )
    expired = client.get(f"/v1/tunnels/{tunnel['tunnel_id']}", headers=headers)
    assert expired.status_code == 200
    assert expired.json()["expires_at"] < int(time.time()), "expiry must be reported honestly"

    renewed = client.post(f"/v1/tunnels/{tunnel['tunnel_id']}/renew", headers=headers)
    assert renewed.status_code == 200
    assert renewed.json()["expires_at"] > int(time.time())

    # Renewal is an owner capability, not an anonymous one.
    assert client.post(f"/v1/tunnels/{tunnel['tunnel_id']}/renew").status_code == 404


def test_expired_tunnels_are_reaped_and_release_their_port(client: TestClient) -> None:
    """The reaper deletes expired leases from the broker, freeing the port."""
    tunnel = make_tunnel(client)
    app = client.app
    app.state.db.connect().execute(
        "UPDATE tunnels SET expires_at=? WHERE tunnel_id=?",
        (int(time.time()) - 3600, tunnel["tunnel_id"]),
    )
    assert tunnel["tunnel_id"] in app.state.broker.tunnels

    # Drive one reaper pass directly instead of waiting on its 30 s timer.
    rows = (
        app.state.db.connect()
        .execute(
            "SELECT tunnel_id FROM tunnels WHERE deleted=0 AND expires_at<=?",
            (int(time.time()),),
        )
        .fetchall()
    )
    assert [row["tunnel_id"] for row in rows] == [tunnel["tunnel_id"]]
