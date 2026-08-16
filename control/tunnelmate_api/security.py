from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from .config import Settings
from .db import Database


def capability_hmac(key: bytes, value: str) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def verify_capability(key: bytes, value: str, expected: str) -> bool:
    return hmac.compare_digest(capability_hmac(key, value), expected)


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024
    )
    return (
        "scrypt$32768$8$1$"
        + base64.urlsafe_b64encode(salt).decode()
        + "$"
        + base64.urlsafe_b64encode(digest).decode()
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        kind, n, r, p, salt64, digest64 = encoded.split("$")
        if kind != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(salt64)
        expected = base64.urlsafe_b64decode(digest64)
        actual = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
            maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def bootstrap_admin(db: Database, username: str, password: str) -> None:
    now = int(time.time())
    encoded = hash_password(password)
    db.connect().execute(
        """INSERT INTO admin_users(username,password_hash,created_at) VALUES(?,?,?)
           ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash""",
        (username, encoded, now),
    )


def audit(
    db: Database,
    event: str,
    actor: str,
    target: str | None = None,
    remote_ip: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    db.connect().execute(
        "INSERT INTO audit_events(event,actor,target,remote_ip,metadata_json,created_at) VALUES(?,?,?,?,?,?)",
        (
            event,
            actor,
            target,
            remote_ip,
            json.dumps(metadata or {}, separators=(",", ":")),
            int(time.time()),
        ),
    )


def bootstrap_cli() -> None:
    parser = argparse.ArgumentParser(description="Create or update a TunnelMate administrator")
    parser.add_argument("username")
    parser.add_argument("--password", help="omit to read TUNNELMATE_ADMIN_PASSWORD")
    args = parser.parse_args()
    settings = Settings.from_env()
    password = args.password or settings.admin_password
    if not password:
        parser.error("--password or TUNNELMATE_ADMIN_PASSWORD is required")
    db = Database(settings.db_path)
    db.initialize()
    bootstrap_admin(db, args.username, password)
    print(f"administrator {args.username!r} initialized")
