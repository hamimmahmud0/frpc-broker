from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    return default if raw is None else raw.lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class Settings:
    db_path: Path
    broker_socket: Path
    public_host: str
    broker_control_port: int
    lease_seconds: int
    secret_key: bytes
    production: bool
    docs_enabled: bool
    secure_cookies: bool
    create_rate_per_minute: int
    max_tunnels_per_ip: int
    max_request_bytes: int
    max_announcement_bytes: int
    max_attribute_depth: int
    max_attribute_keys: int
    admin_username: str | None
    admin_password: str | None
    # Bounded in-memory metric history for the console: interval x history is
    # the visible window, and the whole series is a few hundred KiB.
    metrics_interval_seconds: int = 5
    metrics_history: int = 240

    @classmethod
    def from_env(cls) -> Settings:
        production = _bool("TUNNELMATE_PRODUCTION", False)
        raw_key = os.getenv("TUNNELMATE_SECRET_KEY")
        if production and (not raw_key or len(raw_key) < 32):
            raise RuntimeError("TUNNELMATE_SECRET_KEY (at least 32 characters) is required")
        key = (raw_key or secrets.token_urlsafe(32)).encode()
        return cls(
            db_path=Path(os.getenv("TUNNELMATE_DB", "/var/lib/tunnelmate/control.db")),
            broker_socket=Path(
                os.getenv("TUNNELMATE_BROKER_SOCKET", "/run/tunnelmate/broker.sock")
            ),
            public_host=os.getenv("TUNNELMATE_PUBLIC_HOST", "localhost"),
            broker_control_port=int(os.getenv("TUNNELMATE_BROKER_PORT", "7000")),
            lease_seconds=int(os.getenv("TUNNELMATE_LEASE_SECONDS", "86400")),
            secret_key=key,
            production=production,
            docs_enabled=_bool("TUNNELMATE_DOCS_ENABLED", True),
            secure_cookies=_bool("TUNNELMATE_SECURE_COOKIES", production),
            create_rate_per_minute=int(os.getenv("TUNNELMATE_CREATE_RATE", "10")),
            max_tunnels_per_ip=int(os.getenv("TUNNELMATE_MAX_TUNNELS_PER_IP", "20")),
            max_request_bytes=int(os.getenv("TUNNELMATE_MAX_REQUEST_BYTES", "65536")),
            max_announcement_bytes=int(os.getenv("TUNNELMATE_MAX_ANNOUNCEMENT_BYTES", "16384")),
            max_attribute_depth=int(os.getenv("TUNNELMATE_MAX_ATTRIBUTE_DEPTH", "6")),
            max_attribute_keys=int(os.getenv("TUNNELMATE_MAX_ATTRIBUTE_KEYS", "128")),
            admin_username=os.getenv("TUNNELMATE_ADMIN_USERNAME"),
            admin_password=os.getenv("TUNNELMATE_ADMIN_PASSWORD"),
            metrics_interval_seconds=int(os.getenv("TUNNELMATE_METRICS_INTERVAL", "5")),
            metrics_history=int(os.getenv("TUNNELMATE_METRICS_HISTORY", "240")),
        )
