"""DB-backed investigation storage for RepoTrace v2.

Replaces the per-file JSON store in data/investigations/. Investigations are
optionally scoped to the owning user so each analyst sees their own saved work.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .db import db


async def save_investigation(payload: dict[str, Any], owner_email: str | None = None) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    snapshot = payload.get("snapshot") or {}
    title = payload.get("title") or snapshot.get("full_name") or "RepoTrace investigation"
    inv_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid4().hex[:8]}"
    await db.execute(
        """INSERT INTO investigations(id, owner_email, title, created_at, updated_at, payload)
           VALUES(?,?,?,?,?,?)""",
        (inv_id, owner_email, title, now, now, json.dumps(payload, ensure_ascii=False)),
    )
    return {"id": inv_id, "title": title, "created_at": now}


async def list_investigations(owner_email: str | None = None) -> list[dict[str, Any]]:
    if owner_email:
        rows = await db.fetchall(
            "SELECT id, title, created_at FROM investigations WHERE owner_email = ? ORDER BY created_at DESC LIMIT 200",
            (owner_email,),
        )
    else:
        rows = await db.fetchall(
            "SELECT id, title, created_at FROM investigations ORDER BY created_at DESC LIMIT 200"
        )
    return rows


async def read_investigation(inv_id: str) -> dict[str, Any]:
    row = await db.fetchone("SELECT * FROM investigations WHERE id = ?", (inv_id,))
    if not row:
        raise FileNotFoundError("Investigation not found")
    row["payload"] = json.loads(row["payload"]) if row.get("payload") else {}
    return row
