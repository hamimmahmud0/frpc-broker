"""Host and broker sampling for the operations console.

Everything here is deliberately small: a bounded ring of samples in memory, read
straight from /proc, with no monitoring stack and no disk writes. On a 2 GB VPS
the history costs a few hundred KiB and is lost on restart, which is the right
trade for a service that must never fill its own disk.
"""

from __future__ import annotations

import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# 240 samples at the default 5 s cadence is 20 minutes of history.
DEFAULT_HISTORY = 240

# Counters that are meaningful as a per-second rate rather than a total.
RATE_FIELDS = (
    "rx_bytes_total",
    "tx_bytes_total",
    "udp_bytes_rx",
    "udp_bytes_tx",
    "datagrams_rx_total",
    "datagrams_tx_total",
    "conns_total",
    "streams_total",
)

# Counters worth surfacing as-is.
GAUGE_FIELDS = (
    "tunnel_count",
    "stream_count",
    "ports_used",
    "failed_auths",
    "protocol_errors",
    "agent_reconnects",
    "conns_rate_limited",
    "stream_errors",
    "udp_dropped_queue_full",
    "udp_dropped_oversize",
    "udp_dropped_rate_limit",
    "udp_dropped_no_flow",
    "udp_flow_expired",
    "udp_transport_errors",
)


def _read_first_line(path: str) -> str:
    try:
        with open(path) as handle:
            return handle.readline()
    except OSError:
        return ""


def cpu_times() -> tuple[float, float] | None:
    """Return (busy, total) jiffies from /proc/stat, or None if unavailable."""
    line = _read_first_line("/proc/stat")
    if not line.startswith("cpu "):
        return None
    values = [float(v) for v in line.split()[1:]]
    if len(values) < 4:
        return None
    idle = values[3] + (values[4] if len(values) > 4 else 0.0)
    total = sum(values)
    return total - idle, total


def memory_info() -> dict[str, int]:
    """Total/available/used memory in KiB from /proc/meminfo."""
    info: dict[str, int] = {}
    try:
        with open("/proc/meminfo") as handle:
            for line in handle:
                key, _, rest = line.partition(":")
                if key in {"MemTotal", "MemAvailable", "MemFree", "SwapTotal", "SwapFree"}:
                    info[key] = int(rest.split()[0])
    except OSError:
        return {}
    total = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    return {
        "total_kib": total,
        "available_kib": available,
        "used_kib": max(0, total - available),
        "used_percent": round((total - available) / total * 100, 1) if total else 0.0,
    }


def disk_info(path: str = "/") -> dict[str, Any]:
    """Filesystem usage. The VPS disk budget is small enough to watch closely."""
    try:
        stat = os.statvfs(path)
    except OSError:
        return {}
    total = stat.f_blocks * stat.f_frsize
    free = stat.f_bavail * stat.f_frsize
    used = total - free
    return {
        "total_bytes": total,
        "free_bytes": free,
        "used_bytes": used,
        "used_percent": round(used / total * 100, 1) if total else 0.0,
    }


def process_info(pid: int | None = None) -> dict[str, int]:
    """RSS and open descriptor count for a process (defaults to this one)."""
    pid = pid or os.getpid()
    result = {"rss_kib": 0, "open_fds": 0, "threads": 0}
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    result["rss_kib"] = int(line.split()[1])
                elif line.startswith("Threads:"):
                    result["threads"] = int(line.split()[1])
    except (OSError, ValueError):
        pass
    try:
        result["open_fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        pass
    return result


def find_broker_pid() -> int | None:
    """Locate tunnelmated by scanning /proc, so no pidfile is required."""
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        comm = _read_first_line(f"/proc/{entry}/comm").strip()
        if comm == "tunnelmated":
            return int(entry)
    return None


def load_average() -> list[float]:
    try:
        return [round(v, 2) for v in os.getloadavg()]
    except OSError:
        return [0.0, 0.0, 0.0]


@dataclass
class Sample:
    at: int
    cpu_percent: float
    memory: dict[str, Any]
    disk: dict[str, Any]
    api: dict[str, int]
    broker_process: dict[str, int]
    broker: dict[str, Any]
    rates: dict[str, float]

    def as_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "cpu_percent": self.cpu_percent,
            "memory": self.memory,
            "disk": self.disk,
            "api": self.api,
            "broker_process": self.broker_process,
            "broker": self.broker,
            "rates": self.rates,
        }


@dataclass
class SystemMetrics:
    """Bounded in-memory time series of host and broker samples."""

    history: int = DEFAULT_HISTORY
    samples: deque[Sample] = field(default_factory=deque)
    _last_cpu: tuple[float, float] | None = None
    _last_counters: dict[str, float] = field(default_factory=dict)
    _last_at: float = 0.0
    _broker_pid: int | None = None

    def __post_init__(self) -> None:
        self.samples = deque(maxlen=self.history)

    def _cpu_percent(self) -> float:
        current = cpu_times()
        if current is None:
            return 0.0
        previous, self._last_cpu = self._last_cpu, current
        if previous is None:
            return 0.0
        busy_delta = current[0] - previous[0]
        total_delta = current[1] - previous[1]
        if total_delta <= 0:
            return 0.0
        return round(max(0.0, min(100.0, busy_delta / total_delta * 100)), 1)

    def _rates(self, counters: dict[str, Any], now: float) -> dict[str, float]:
        rates: dict[str, float] = {}
        elapsed = now - self._last_at if self._last_at else 0.0
        for name in RATE_FIELDS:
            value = counters.get(name)
            if not isinstance(value, (int, float)):
                continue
            previous = self._last_counters.get(name)
            if previous is not None and elapsed > 0:
                # Counters reset to zero when the broker restarts; report 0
                # rather than a negative spike.
                rates[name] = round(max(0.0, (value - previous) / elapsed), 2)
            self._last_counters[name] = float(value)
        self._last_at = now
        return rates

    def collect(self, broker_status: dict[str, Any] | None) -> Sample:
        status = broker_status or {}
        now = time.time()
        if self._broker_pid is None or not os.path.exists(f"/proc/{self._broker_pid}"):
            self._broker_pid = find_broker_pid()
        sample = Sample(
            at=int(now),
            cpu_percent=self._cpu_percent(),
            memory={**memory_info(), "load_average": load_average()},
            disk=disk_info(),
            api=process_info(),
            broker_process=process_info(self._broker_pid) if self._broker_pid else {},
            broker={name: status.get(name, 0) for name in GAUGE_FIELDS},
            rates=self._rates(status, now),
        )
        self.samples.append(sample)
        return sample

    def latest(self) -> dict[str, Any] | None:
        return self.samples[-1].as_dict() if self.samples else None

    def series(self, limit: int | None = None) -> list[dict[str, Any]]:
        items = list(self.samples)
        if limit:
            items = items[-limit:]
        return [s.as_dict() for s in items]
