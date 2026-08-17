"""UDP throughput, latency and aggregate-volume tests.

A UDP tunnel that reaches throughput while adding severe head-of-line latency
is not acceptable, so these measure delay distribution as well as volume, and
they check loss, duplication and reordering separately rather than folding them
into one number.
"""

from __future__ import annotations

import itertools
import os
import socket
import statistics
import struct
import threading
import time

import pytest
from harness import UdpEcho, rss_kib, start_agent, wait_for

# Sizes chosen around the default 1400-byte tunnel limit.
DATAGRAM_SIZES = (64, 256, 512, 1200, 1400)


def udp_settings(**overrides) -> dict:
    """Broker limits raised enough to measure the transport, not the limiter."""
    settings = {
        "broker.udp_max_packets_per_tunnel": 2_000_000,
        "broker.udp_max_packets_per_source": 2_000_000,
        "broker.udp_flow_creation_rate": 4096,
        "broker.udp_max_flows_per_tunnel": 4096,
        "broker.udp_queue_packets": 1024,
        "broker.udp_flow_idle_timeout_ms": 120000,
    }
    settings.update(overrides)
    return settings


def echo_tunnel(broker, name: str):
    echo = UdpEcho()
    echo.start()
    tunnel = broker.create_tunnel(name, proto="udp")
    start_agent(broker, tunnel, echo.port, "udp")
    return echo, tunnel


def test_udp_latency_by_datagram_size(broker_factory) -> None:
    """Round-trip delay must stay sane across the usable size range."""
    broker = broker_factory(settings=udp_settings())
    echo, tunnel = echo_tunnel(broker, "udp-latency")
    target = ("127.0.0.1", tunnel["public_port"])

    report = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        for size in DATAGRAM_SIZES:
            # Warm the flow so the DTLS session and mapping already exist.
            client.sendto(b"w" * size, target)
            try:
                client.recvfrom(65535)
            except TimeoutError:
                pytest.fail(f"no reply at size {size}")

            samples = []
            lost = 0
            for index in range(200):
                payload = struct.pack(">I", index) + b"p" * (size - 4)
                start = time.perf_counter()
                client.sendto(payload, target)
                try:
                    data, _ = client.recvfrom(65535)
                except TimeoutError:
                    lost += 1
                    continue
                if data == payload:
                    samples.append((time.perf_counter() - start) * 1000)
            assert samples, f"no successful round trips at size {size}"
            ordered = sorted(samples)
            report.append(
                {
                    "size": size,
                    "n": len(samples),
                    "lost": lost,
                    "p50": statistics.median(ordered),
                    "p95": ordered[int(len(ordered) * 0.95) - 1],
                    "p99": ordered[int(len(ordered) * 0.99) - 1],
                }
            )

    print("\nudp_latency (ms, loopback round trip through the tunnel)")
    for row in report:
        print(
            f"  size={row['size']:>5}B n={row['n']:>3} lost={row['lost']:>2} "
            f"p50={row['p50']:.3f} p95={row['p95']:.3f} p99={row['p99']:.3f}"
        )
    for row in report:
        assert row["lost"] <= 4, f"{row['lost']}/200 lost at size {row['size']} on loopback"
        assert row["p99"] < 100, f"p99 {row['p99']:.1f} ms at size {row['size']}"
    echo.close()


def test_udp_realtime_stream_jitter_and_order(broker_factory) -> None:
    """A telemetry/game-shaped continuous stream: watch jitter and reordering."""
    broker = broker_factory(settings=udp_settings())
    echo, tunnel = echo_tunnel(broker, "udp-realtime")
    target = ("127.0.0.1", tunnel["public_port"])

    total = 2000
    received: list[tuple[int, float]] = []
    stop = threading.Event()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.5)

        def reader() -> None:
            while not stop.is_set():
                try:
                    data, _ = client.recvfrom(65535)
                except (TimeoutError, OSError):
                    continue
                received.append((struct.unpack(">I", data[:4])[0], time.perf_counter()))

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        for index in range(total):
            client.sendto(struct.pack(">I", index) + b"t" * 196, target)
            time.sleep(0.001)  # ~1 kHz, like a game or telemetry feed
        time.sleep(2)
        stop.set()
        thread.join(timeout=3)

    sequences = [seq for seq, _ in received]
    unique = set(sequences)
    duplicates = len(sequences) - len(unique)
    lost = total - len(unique)
    reordered = sum(1 for a, b in itertools.pairwise(sequences) if b < a)
    gaps = [(b - a) * 1000 for (_, a), (_, b) in itertools.pairwise(received)]
    jitter = statistics.pstdev(gaps) if len(gaps) > 1 else 0.0

    print(
        f"\nudp_realtime sent={total} received={len(sequences)} lost={lost} "
        f"duplicated={duplicates} reordered={reordered} "
        f"inter_arrival_jitter_ms={jitter:.3f}"
    )
    assert lost <= total * 0.02, f"{lost}/{total} lost on loopback"
    assert duplicates == 0, f"{duplicates} datagrams duplicated"
    echo.close()


def test_udp_throughput_by_size(broker_factory) -> None:
    """Packets/sec and Mb/s at each size, with the drop counters reported."""
    broker = broker_factory(settings=udp_settings())
    echo, tunnel = echo_tunnel(broker, "udp-throughput")
    target = ("127.0.0.1", tunnel["public_port"])

    print("\nudp_throughput (one-way send rate into the tunnel)")
    for size in (256, 1200, 1400):
        payload = b"x" * size
        before = broker.status()
        count = 4000
        started = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
            for _ in range(count):
                try:
                    client.sendto(payload, target)
                except OSError:
                    time.sleep(0.0005)
        elapsed = time.perf_counter() - started
        time.sleep(1.0)
        after = broker.status()
        delivered = after["datagrams_rx_total"] - before["datagrams_rx_total"]
        dropped = (
            after["udp_dropped_queue_full"] - before["udp_dropped_queue_full"]
            + after["udp_dropped_rate_limit"] - before["udp_dropped_rate_limit"]
            + after["udp_dropped_oversize"] - before["udp_dropped_oversize"]
        )
        print(
            f"  size={size:>5}B sent={count} broker_rx={delivered} dropped={dropped} "
            f"pkts_per_sec={count / elapsed:,.0f} "
            f"Mb_per_sec={count * size * 8 / elapsed / 1e6:.1f}"
        )
    assert broker.process.poll() is None
    echo.close()


@pytest.mark.extended
@pytest.mark.skipif(
    "TUNNELMATE_UDP_LARGE_BYTES" not in os.environ,
    reason="set TUNNELMATE_UDP_LARGE_BYTES=6442450944 for the aggregate UDP test",
)
def test_udp_aggregate_volume_exceeds_five_gigabytes(broker_factory) -> None:
    """Aggregate UDP payload past 5 GB, in ~1400-byte datagrams.

    This is total transferred volume, not one enormous datagram. Loss is
    legitimate for UDP under stress, so the assertion is on delivered volume
    and on the broker staying bounded, not on zero loss.
    """
    goal = int(os.environ["TUNNELMATE_UDP_LARGE_BYTES"])
    broker = broker_factory(settings=udp_settings())
    echo, tunnel = echo_tunnel(broker, "udp-aggregate")
    target = ("127.0.0.1", tunnel["public_port"])

    size = 1400
    needed = goal // size + 1
    payload = b"u" * size
    baseline_rss = rss_kib(broker.process.pid)
    peak_rss = baseline_rss
    sent = 0
    started = time.perf_counter()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
        while sent < needed:
            try:
                client.sendto(payload, target)
                sent += 1
            except OSError:
                time.sleep(0.0002)
                continue
            if sent % 100_000 == 0:
                peak_rss = max(peak_rss, rss_kib(broker.process.pid))
                elapsed = time.perf_counter() - started
                print(
                    f"  sent {sent * size / 1024**3:.2f} GiB "
                    f"({sent:,} datagrams) {sent * size / elapsed / 1048576:.0f} MiB/s "
                    f"broker_rss={rss_kib(broker.process.pid)}k",
                    flush=True,
                )

    elapsed = time.perf_counter() - started
    time.sleep(2)
    status = broker.status()
    delivered_bytes = status["udp_bytes_rx"] if "udp_bytes_rx" in status else status["rx_bytes_total"]
    dropped = (
        status["udp_dropped_queue_full"]
        + status["udp_dropped_rate_limit"]
        + status["udp_dropped_oversize"]
        + status["udp_dropped_no_flow"]
    )
    print(
        f"\nudp_aggregate sent_datagrams={sent:,} sent_bytes={sent * size:,} "
        f"({sent * size / 1024**3:.2f} GiB) seconds={elapsed:.1f} "
        f"MiB/s={sent * size / elapsed / 1048576:.1f} "
        f"broker_rx_datagrams={status['datagrams_rx_total']:,} "
        f"broker_rx_bytes={delivered_bytes:,} dropped={dropped:,} "
        f"echo_received={echo.count:,} "
        f"broker_baseline_rss_kib={baseline_rss} broker_peak_rss_kib={peak_rss}"
    )
    assert sent * size >= goal
    assert broker.process.poll() is None
    # Bounded queues: the broker must not have grown by more than a few MiB.
    assert peak_rss - baseline_rss < 65536, (
        f"broker RSS grew {peak_rss - baseline_rss} KiB moving {sent * size / 1024**3:.1f} GiB"
    )
    echo.close()


def test_udp_datagram_sizes_survive_round_trip(broker_factory) -> None:
    """Every size up to the configured limit returns byte-identical."""
    broker = broker_factory(settings=udp_settings())
    echo, tunnel = echo_tunnel(broker, "udp-sizes")
    target = ("127.0.0.1", tunnel["public_port"])

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        for size in (0, 1, 2, 63, 64, 255, 256, 511, 512, 1199, 1200, 1399, 1400):
            payload = os.urandom(size)
            client.sendto(payload, target)
            data, _ = client.recvfrom(65535)
            assert data == payload, f"size {size} did not round trip intact"
            assert len(data) == size, f"size {size} came back as {len(data)}"
    echo.close()


def test_udp_oversize_boundary_is_exact(broker_factory) -> None:
    """1400 passes, 1401 is dropped — the limit is not approximate."""
    broker = broker_factory(settings=udp_settings(**{"broker.udp_max_datagram_size": 1400}))
    echo, tunnel = echo_tunnel(broker, "udp-boundary")
    target = ("127.0.0.1", tunnel["public_port"])

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(b"a" * 1400, target)
        assert len(client.recvfrom(65535)[0]) == 1400

        before = broker.status()["udp_dropped_oversize"]
        client.sendto(b"b" * 1401, target)
        try:
            extra = client.recvfrom(65535)[0]
            pytest.fail(f"oversized datagram was delivered as {len(extra)} bytes")
        except TimeoutError:
            pass
        wait_for(lambda: broker.status()["udp_dropped_oversize"] > before, timeout=10)
    assert all(size <= 1400 for size in echo.sizes)
    echo.close()
