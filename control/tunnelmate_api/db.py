from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS tunnels (
  tunnel_id TEXT PRIMARY KEY,
  protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
  scope TEXT NOT NULL CHECK(scope IN ('open','closed')),
  public_port INTEGER NOT NULL,
  peer_address TEXT NOT NULL,
  agent_secret_hmac TEXT NOT NULL,
  shared_token_hmac TEXT NOT NULL DEFAULT '',
  management_hmac TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  deleted INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tunnels_scope ON tunnels(scope);
CREATE INDEX IF NOT EXISTS idx_tunnels_status ON tunnels(enabled, deleted);
CREATE INDEX IF NOT EXISTS idx_tunnels_created ON tunnels(created_at);
CREATE INDEX IF NOT EXISTS idx_tunnels_expires ON tunnels(expires_at);
CREATE INDEX IF NOT EXISTS idx_tunnels_source ON tunnels(source_ip);

CREATE TABLE IF NOT EXISTS announcements (
  announcement_id TEXT PRIMARY KEY,
  tunnel_id TEXT NOT NULL REFERENCES tunnels(tunnel_id),
  protocol TEXT NOT NULL,
  scope TEXT NOT NULL,
  peer_address TEXT NOT NULL,
  service_name TEXT NOT NULL,
  service_id TEXT NOT NULL,
  llms TEXT NOT NULL,
  attributes_json TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  verified INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ann_tunnel ON announcements(tunnel_id);
CREATE INDEX IF NOT EXISTS idx_ann_service_id ON announcements(service_id);
CREATE INDEX IF NOT EXISTS idx_ann_service_name ON announcements(service_name);
CREATE INDEX IF NOT EXISTS idx_ann_scope ON announcements(scope);
CREATE INDEX IF NOT EXISTS idx_ann_protocol ON announcements(protocol);

CREATE TABLE IF NOT EXISTS admin_users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hmac TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES admin_users(user_id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON admin_sessions(expires_at);

CREATE TABLE IF NOT EXISTS blocked_ips (
  cidr TEXT PRIMARY KEY,
  reason TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event TEXT NOT NULL,
  actor TEXT NOT NULL,
  target TEXT,
  remote_ip TEXT,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
"""


class Database:
    def __init__(self, path: Path):
        self.path = path
        self._local = threading.local()

    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def initialize(self) -> None:
        self.connect().executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        else:
            conn.commit()

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
