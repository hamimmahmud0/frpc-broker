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


def test_console_contains_wide_tables_inside_the_viewport(client: TestClient) -> None:
    """Wide table content must scroll locally instead of widening the page."""
    login(client)
    css = client.get("/static/admin.css").text
    assert "grid-template-columns:minmax(0,1fr)" in css
    assert "section{min-width:0" in css
    assert ".table-wrap{width:100%;max-width:100%;overflow:auto" in css


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


# ---------------------------------------------------------------------------
# llms.txt
# ---------------------------------------------------------------------------


def test_llms_txt_is_public_and_plain_text(client: TestClient) -> None:
    """It must be readable with no credential at all — that is the point."""
    response = client.get("/llms.txt")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "charset=utf-8" in response.headers["content-type"]


def test_llms_txt_documents_the_whole_service(client: TestClient) -> None:
    """An agent should be able to drive the API from this file alone."""
    body = client.get("/llms.txt").text

    # Enough to actually make requests.
    for fragment in (
        "/v1/tunnels",
        "/v1/announce",
        "/v1/announce/search",
        "X-Tunnel-Management-Secret",
        "openapi.json",
        "agent.tunnel_id",
        "tunnelmate-peer",
    ):
        assert fragment in body, fragment

    # Enough to understand the capability model.
    for fragment in ("agent_secret", "management_secret", "shared_token"):
        assert fragment in body, fragment

    # Enough to handle failure.
    for fragment in ("TUNNEL_NOT_FOUND", "RATE_LIMITED", "BROKER_UNAVAILABLE", "request_id"):
        assert fragment in body, fragment

    # The honest parts, which matter most for an autonomous caller.
    assert "not end-to-end" in body
    assert "do not resume" in body.lower()
    assert "Important limitations" in body
    assert "Guidance for automated agents" in body


def test_llms_txt_leaks_no_secret(client: TestClient) -> None:
    """It is public, so it must never carry a real credential."""
    tunnel = make_tunnel(client)
    body = client.get("/llms.txt").text
    assert tunnel["agent_secret"] not in body
    assert tunnel["management_secret"] not in body
    assert tunnel["tunnel_id"] not in body
    # The admin password must not appear either.
    assert ADMIN_PASSWORD not in body


def test_llms_txt_uses_the_origin_the_caller_reached(client: TestClient) -> None:
    """Examples must name a host the reader can actually resolve."""
    direct = client.get("/llms.txt").text
    assert "testserver" in direct

    # Behind a reverse proxy the forwarded origin wins, so copy-pasted examples
    # point at the public address rather than the loopback bind.
    proxied = client.get(
        "/llms.txt",
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "tunnel.example.com"},
    ).text
    assert "https://tunnel.example.com" in proxied
    assert "https://tunnel.example.com/openapi.json" in proxied


def test_llms_txt_has_no_unresolved_placeholders(client: TestClient) -> None:
    """A stray format field would hand an agent a literal brace as a value."""
    import re

    body = client.get("/llms.txt").text
    # {id} and {name} are intentional path placeholders in the endpoint
    # reference; nothing else should survive.
    leftover = {m for m in re.findall(r"\{[a-z_]+\}", body)} - {"{id}", "{name}"}
    assert not leftover, leftover


def test_llms_txt_says_where_the_software_comes_from(client: TestClient) -> None:
    """"Install it" is useless without naming what to install and from where.

    Every route into the product has to be reachable from this file: the
    repository, the build, the binary that actually carries traffic, and the
    pip specifier. A reader with only this URL must not have to guess.
    """
    body = client.get("/llms.txt").text

    assert "git clone" in body
    assert "cmake" in body
    assert "#subdirectory=python-sdk" in body

    # The build prerequisites, because the compile fails without them.
    for fragment in ("libuv1-dev", "libssl-dev", "OpenSSL 3.2"):
        assert fragment in body, fragment

    # The binaries, named, so the reader knows what the build produced.
    for fragment in ("tunnelmate-agent", "tunnelmate-peer", "tunnelmated"):
        assert fragment in body, fragment


def test_llms_txt_warns_off_the_pypi_name_collision(client: TestClient) -> None:
    """`pip install tunnelmate` fetches an unrelated project of the same name.

    Following that instruction installs a stranger's code, which is worse than
    a missing instruction, so the document must say so explicitly rather than
    merely omitting it.
    """
    body = client.get("/llms.txt").text
    assert "pip install tunnelmate" in body
    assert "unrelated third-party package" in body
    # And it must never be the recommended form: every install line is the
    # source specifier.
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("pip install ") and "subdirectory=python-sdk" not in stripped:
            assert stripped == "pip install tunnelmate", stripped


def test_llms_txt_uses_the_flag_the_agent_actually_accepts(client: TestClient) -> None:
    """The agent takes -c; --config makes it print usage and exit 1."""
    body = client.get("/llms.txt").text
    assert "tunnelmate-agent -c " in body
    assert "tunnelmate-agent --config" not in body


def test_llms_txt_covers_certificate_trust_and_udp_extra_key(client: TestClient) -> None:
    """The two things that silently break a first attempt.

    A self-signed deployment fails verification unless the reader fetches the
    certificate, and a UDP agent needs `agent.broker_udp_port`, which has no
    TCP counterpart and so is easy to leave out.
    """
    body = client.get("/llms.txt").text
    assert "/v1/broker-certificate" in body
    assert "agent.ca_path" in body
    assert "agent.broker_udp_port" in body


def test_broker_certificate_is_public_when_present(tmp_path: Path, client: TestClient) -> None:
    """A TLS server hands this to anyone who connects; publishing adds nothing."""
    cert = tmp_path / "broker.crt"
    cert.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    client.app.state.settings.broker_cert_path = cert

    response = client.get("/v1/broker-certificate")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-pem-file")
    assert "BEGIN CERTIFICATE" in response.text


def test_broker_certificate_never_serves_a_private_key(tmp_path: Path, client: TestClient) -> None:
    """A path typo pointing at broker.key would publish the key to the Internet.

    The check is on content rather than filename because that is what actually
    determines the damage.
    """
    key = tmp_path / "broker.key"
    key.write_text("-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n")
    client.app.state.settings.broker_cert_path = key

    response = client.get("/v1/broker-certificate")
    assert response.status_code == 404
    assert "PRIVATE KEY" not in response.text


def test_broker_certificate_absent_is_a_clean_404(tmp_path: Path, client: TestClient) -> None:
    """A publicly trusted deployment has nothing to publish, and must not 500."""
    client.app.state.settings.broker_cert_path = tmp_path / "does-not-exist.crt"
    response = client.get("/v1/broker-certificate")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "CERTIFICATE_UNAVAILABLE"


def _releases(tmp_path: Path, client: TestClient) -> Path:
    """Point the running app at a release directory and return it."""
    releases = tmp_path / "releases"
    releases.mkdir()
    client.app.state.settings.release_dir = releases
    return releases


def test_downloads_index_lists_files_with_absolute_urls(
    tmp_path: Path, client: TestClient
) -> None:
    """A relative name would make the caller guess how to fetch it."""
    releases = _releases(tmp_path, client)
    (releases / "tunnelmate-0.1.0-linux-x86_64.tar.gz").write_bytes(b"payload")
    (releases / "SHA256SUMS").write_text("abc  ./tunnelmate-0.1.0-linux-x86_64.tar.gz\n")

    body = client.get("/v1/downloads", headers={"X-Forwarded-Host": "tunnel.example.com"}).json()
    names = {item["name"] for item in body["items"]}
    assert "tunnelmate-0.1.0-linux-x86_64.tar.gz" in names
    for item in body["items"]:
        assert item["url"].startswith("http://tunnel.example.com/v1/download/")
    assert body["checksums"].endswith("/v1/download/SHA256SUMS")


def test_downloads_index_is_empty_not_broken_without_a_release_dir(
    tmp_path: Path, client: TestClient
) -> None:
    """Most deployments publish nothing; that is a state, not a fault."""
    client.app.state.settings.release_dir = tmp_path / "nothing-here"
    body = client.get("/v1/downloads").json()
    assert body["items"] == []
    assert body["checksums"] is None


def test_download_serves_the_published_bytes(tmp_path: Path, client: TestClient) -> None:
    releases = _releases(tmp_path, client)
    (releases / "tunnelmate-0.1.0-linux-x86_64.tar.gz").write_bytes(b"\x1f\x8bpayload")

    response = client.get("/v1/download/tunnelmate-0.1.0-linux-x86_64.tar.gz")
    assert response.status_code == 200
    assert response.content == b"\x1f\x8bpayload"


def test_download_refuses_to_walk_out_of_the_release_directory(
    tmp_path: Path, client: TestClient
) -> None:
    """The name comes from the URL, so traversal is the obvious attack.

    Encoded separators are what actually reaches the handler after Starlette
    decodes the path, so they are tested alongside the plain form.
    """
    releases = _releases(tmp_path, client)
    (tmp_path / "secret.txt").write_text("private key material")
    (releases / "ok.tar.gz").write_bytes(b"fine")

    for name in ("../secret.txt", "..%2Fsecret.txt", "%2e%2e%2fsecret.txt", ".hidden", "sub/x"):
        response = client.get(f"/v1/download/{name}")
        assert response.status_code == 404, name
        assert "private key material" not in response.text, name


def test_download_refuses_a_symlink_pointing_outside(tmp_path: Path, client: TestClient) -> None:
    """A whitelisted name is not enough if the file itself escapes."""
    releases = _releases(tmp_path, client)
    (tmp_path / "outside.bin").write_text("not for publication")
    (releases / "escape.tar.gz").symlink_to(tmp_path / "outside.bin")

    response = client.get("/v1/download/escape.tar.gz")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DOWNLOAD_UNAVAILABLE"


def test_llms_txt_offers_the_prebuilt_download_path(tmp_path: Path, client: TestClient) -> None:
    """Building needs OpenSSL 3.2, which two current LTS distros do not ship.

    A reader stuck there has no way forward from a build-only document, so the
    download route has to be stated before the build, not after it.
    """
    releases = _releases(tmp_path, client)
    (releases / "tunnelmate-0.1.0-linux-x86_64.tar.gz").write_bytes(b"x")
    (releases / "tunnelmate-0.1.0-linux-aarch64.tar.gz").write_bytes(b"x")

    body = client.get("/llms.txt").text
    assert "/v1/download/tunnelmate-0.1.0-linux-$ARCH.tar.gz" in body
    # Both published architectures are named, or half the readers cannot tell
    # whether theirs is covered.
    assert "tunnelmate-0.1.0-linux-x86_64.tar.gz" in body
    assert "tunnelmate-0.1.0-linux-aarch64.tar.gz" in body
    assert body.index("/v1/downloads") < body.index("git clone")


def test_llms_txt_never_advertises_a_download_that_does_not_exist(
    tmp_path: Path, client: TestClient
) -> None:
    """An operator who publishes nothing must not get a document full of 404s.

    The version in the filename is read from disk for exactly this reason, so
    the empty case has to degrade to "build from source" rather than to a
    plausible-looking URL.
    """
    client.app.state.settings.release_dir = tmp_path / "empty"
    body = client.get("/llms.txt").text
    assert "publishes no pre-built binaries" in body
    assert "/v1/download/tunnelmate-" not in body
    # The build route must still be fully present as the way forward.
    assert "git clone" in body and "cmake -S . -B build" in body


def _request(peer: str, forwarded: str | None = None):
    """A bare Request with a chosen socket peer and X-Forwarded-For."""
    from starlette.requests import Request

    headers = [(b"host", b"broker.test")]
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": headers,
            "client": (peer, 40000),
            "scheme": "http",
            "server": ("127.0.0.1", 9000),
        }
    )


def test_client_ip_ignores_forwarded_header_from_an_untrusted_peer() -> None:
    """Anyone reaching the API directly can write whatever they like there.

    Honouring it would let a caller pick a fresh address per request and walk
    straight past every per-IP limit.
    """
    from tunnelmate_api.main import client_ip

    assert client_ip(_request("203.0.113.9", "198.51.100.1")) == "203.0.113.9"


def test_client_ip_uses_the_proxys_forwarded_address() -> None:
    """The whole point: behind a proxy the socket peer is always the proxy."""
    from tunnelmate_api.main import client_ip

    assert client_ip(_request("127.0.0.1", "198.51.100.1")) == "198.51.100.1"


def test_client_ip_takes_the_rightmost_hop_not_the_leftmost() -> None:
    """A proxy appends; everything to its left came from the client.

    Here the client sent "1.2.3.4" and Caddy appended the address it really
    saw. Trusting the leftmost entry would reinstate the spoof this function
    exists to prevent.
    """
    from tunnelmate_api.main import client_ip

    assert client_ip(_request("127.0.0.1", "1.2.3.4, 198.51.100.1")) == "198.51.100.1"


def test_client_ip_falls_back_when_the_header_is_absent_or_junk() -> None:
    """A direct hit on the loopback port, or a mangled header, must not 500."""
    from tunnelmate_api.main import client_ip

    assert client_ip(_request("127.0.0.1")) == "127.0.0.1"
    assert client_ip(_request("127.0.0.1", "not-an-address")) == "127.0.0.1"
    assert client_ip(_request("127.0.0.1", " , ")) == "127.0.0.1"


def test_client_ip_folds_ipv4_mapped_form_into_one_bucket() -> None:
    """Otherwise one caller holds two independent quotas."""
    from tunnelmate_api.main import client_ip

    assert client_ip(_request("127.0.0.1", "::ffff:203.0.113.7")) == "203.0.113.7"


def test_per_ip_tunnel_limit_is_per_ip_and_not_global(tmp_path: Path) -> None:
    """The failure this fixes: one caller's tunnels locked out everyone else.

    With the proxy's address charged for every request, max_tunnels_per_ip
    became a global ceiling — the twentieth live tunnel anywhere on the
    Internet made the API refuse the next caller, whoever they were.
    """
    conf = settings(tmp_path)
    conf.max_tunnels_per_ip = 2
    app = create_app(conf)
    app.state.broker = FakeBroker()
    app.state.db.initialize()

    with TestClient(app, client=("127.0.0.1", 40000)) as client:
        noisy = {"X-Forwarded-For": "198.51.100.1"}
        for _ in range(conf.max_tunnels_per_ip):
            created = client.post(
                "/v1/tunnels", json={"scope": "open", "protocol": "tcp"}, headers=noisy
            )
            assert created.status_code == 201

        exhausted = client.post(
            "/v1/tunnels", json={"scope": "open", "protocol": "tcp"}, headers=noisy
        )
        assert exhausted.status_code == 429
        assert exhausted.json()["error"]["code"] == "TUNNEL_LIMIT"

        # A different caller is unaffected. This is the assertion that fails
        # against the old behaviour.
        other = client.post(
            "/v1/tunnels",
            json={"scope": "open", "protocol": "tcp"},
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
        assert other.status_code == 201
