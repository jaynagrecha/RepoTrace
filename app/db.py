"""Async SQLite persistence layer for RepoTrace v2.

Replaces the JSON-file managers (auth/usage/payments/watches/investigations).
On Render's paid tier this database lives on the mounted persistent disk
(set REPOTRACE_DB_PATH=/var/data/repotrace.db), so accounts, credits, and
watch snapshots survive restarts and redeploys.

Design notes:
* WAL mode + a single shared connection guarded by an asyncio.Lock gives us
  safe concurrent access from the async app without the read-modify-write races
  the old JSON files had.
* All money/identity mutations (credit grant/consume) run inside a single
  transaction via the `transaction()` context manager.
* Schema is created/migrated idempotently on startup. The access patterns are
  deliberately simple (no SQLite-specific SQL beyond pragmas) so moving to
  Postgres later is mostly a driver swap.
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Iterable

import aiosqlite

DB_PATH = os.getenv("REPOTRACE_DB_PATH", "data/repotrace.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email                   TEXT PRIMARY KEY,
    org_domain              TEXT,
    org_name                TEXT,
    password_salt           TEXT NOT NULL,
    password_hash           TEXT NOT NULL,
    github_token            TEXT DEFAULT '',
    github_token_fingerprint TEXT DEFAULT '',
    paid_credits            INTEGER NOT NULL DEFAULT 0,
    searches                INTEGER NOT NULL DEFAULT 0,
    email_verified          INTEGER NOT NULL DEFAULT 0,
    created_at              TEXT NOT NULL,
    last_login              TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- Daily + burst usage keyed by identity (user email when authenticated,
-- otherwise "ip:<addr>" for anonymous callers).
CREATE TABLE IF NOT EXISTS usage_daily (
    identity    TEXT NOT NULL,
    day         TEXT NOT NULL,
    searches    INTEGER NOT NULL DEFAULT 0,
    units       INTEGER NOT NULL DEFAULT 0,
    last_seen   INTEGER,
    PRIMARY KEY (identity, day)
);

CREATE TABLE IF NOT EXISTS usage_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    identity  TEXT NOT NULL,
    ts        INTEGER NOT NULL,
    endpoint  TEXT,
    units     INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_usage_events_identity_ts ON usage_events(identity, ts);

-- Anonymous (IP-scoped) paid credits, kept separate from per-user credits so
-- account credits are never consumable by a different visitor sharing an IP.
CREATE TABLE IF NOT EXISTS anon_credits (
    ip       TEXT PRIMARY KEY,
    credits  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    order_id     TEXT PRIMARY KEY,
    receipt      TEXT,
    identity     TEXT,            -- user email or ip:<addr> at order time
    ip           TEXT,
    units        INTEGER NOT NULL DEFAULT 1,
    amount       INTEGER,
    currency     TEXT DEFAULT 'INR',
    status       TEXT DEFAULT 'created',
    mode         TEXT,
    created_at   INTEGER,
    paid_at      INTEGER,
    payment_id   TEXT,
    paid_source  TEXT,
    provider_response TEXT
);

CREATE TABLE IF NOT EXISTS payments (
    payment_id  TEXT PRIMARY KEY,
    order_id    TEXT,
    status      TEXT,
    amount      INTEGER,
    currency    TEXT,
    method      TEXT,
    email       TEXT,
    contact     TEXT,
    mode        TEXT,
    verified_at INTEGER
);

CREATE TABLE IF NOT EXISTS credit_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    identity   TEXT,
    ip         TEXT,
    units      INTEGER,
    source     TEXT,
    order_id   TEXT,
    payment_id TEXT
);

CREATE TABLE IF NOT EXISTS watches (
    watch_id     TEXT PRIMARY KEY,
    owner_email  TEXT,
    target_input TEXT NOT NULL,
    target_type  TEXT,
    notify_email TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    interval_min INTEGER NOT NULL DEFAULT 360,
    snapshot     TEXT,            -- JSON of last snapshot
    last_run     TEXT,
    next_run     TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_watches_next_run ON watches(enabled, next_run);

CREATE TABLE IF NOT EXISTS investigations (
    id          TEXT PRIMARY KEY,
    owner_email TEXT,
    title       TEXT,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    payload     TEXT NOT NULL    -- JSON
);
CREATE TABLE IF NOT EXISTS email_otps (
    email       TEXT PRIMARY KEY,
    code_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_sent   TEXT
);

CREATE TABLE IF NOT EXISTS password_resets (
    token_hash  TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    request_ip  TEXT
);
CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email);
CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);
"""


class Database:
    def __init__(self, path: str = DB_PATH):
        self.path = path
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA foreign_keys=ON;")
        await self._conn.execute("PRAGMA busy_timeout=5000;")
        await self._conn.executescript(SCHEMA)
        await self._migrate()
        await self._conn.commit()

    async def _migrate(self) -> None:
        """Idempotent migrations for databases created before a column existed."""
        # email_verified added for OTP verification.
        cur = await self._conn.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in await cur.fetchall()}
        if "email_verified" not in cols:
            # Existing accounts predate verification; treat them as verified so
            # we don't lock out users who registered before this feature.
            await self._conn.execute(
                "ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1"
            )

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("Database not connected; call connect() on startup.")
        return self._conn

    @asynccontextmanager
    async def transaction(self):
        """Serialize writes through the shared connection lock."""
        async with self._lock:
            try:
                yield self.conn
                await self.conn.commit()
            except Exception:
                await self.conn.rollback()
                raise

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> dict | None:
        async with self.conn.execute(sql, tuple(params)) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        async with self.conn.execute(sql, tuple(params)) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> None:
        async with self._lock:
            await self.conn.execute(sql, tuple(params))
            await self.conn.commit()


# Singleton used across the app.
db = Database()
