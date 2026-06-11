"""Watchlist management for RepoTrace.

CRUD over the existing `watches` table, always scoped to the authenticated
user's email so one user cannot see or modify another's watches. The scheduler
already honors `enabled` and `interval_min`, so pause/resume/edit take effect on
the next tick with no scheduler changes.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import db


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def list_watches(owner_email: str) -> list[dict[str, Any]]:
    rows = await db.fetchall(
        """SELECT watch_id, target_input, target_type, notify_email, enabled,
                  interval_min, last_run, next_run, created_at, snapshot
           FROM watches WHERE owner_email = ? ORDER BY created_at DESC""",
        (owner_email,),
    )
    out = []
    for r in rows:
        snap = {}
        if r.get("snapshot"):
            try:
                snap = json.loads(r["snapshot"])
            except Exception:
                snap = {}
        out.append({
            "watch_id": r["watch_id"],
            "target": r["target_input"],
            "target_type": r["target_type"],
            "notify_email": r["notify_email"],
            "enabled": bool(r["enabled"]),
            "interval_min": r["interval_min"],
            "last_run": r["last_run"],
            "next_run": r["next_run"],
            "created_at": r["created_at"],
            "last_risk": (snap.get("risk") or {}).get("level") if isinstance(snap, dict) else None,
            "repo_count": snap.get("repo_count") if isinstance(snap, dict) else None,
        })
    return out


async def _owned(owner_email: str, watch_id: str) -> bool:
    row = await db.fetchone(
        "SELECT 1 FROM watches WHERE watch_id = ? AND owner_email = ?",
        (watch_id, owner_email),
    )
    return bool(row)


async def set_enabled(owner_email: str, watch_id: str, enabled: bool) -> dict[str, Any]:
    if not await _owned(owner_email, watch_id):
        raise PermissionError("Watch not found for this account.")
    # When resuming, schedule the next run soon rather than leaving a stale time.
    if enabled:
        next_run = _now_iso()
        await db.execute(
            "UPDATE watches SET enabled = 1, next_run = ? WHERE watch_id = ? AND owner_email = ?",
            (next_run, watch_id, owner_email),
        )
    else:
        await db.execute(
            "UPDATE watches SET enabled = 0 WHERE watch_id = ? AND owner_email = ?",
            (watch_id, owner_email),
        )
    return {"ok": True, "watch_id": watch_id, "enabled": enabled}


async def set_interval(owner_email: str, watch_id: str, interval_min: int) -> dict[str, Any]:
    if not await _owned(owner_email, watch_id):
        raise PermissionError("Watch not found for this account.")
    interval_min = max(30, min(10080, int(interval_min)))
    # Recompute next_run from the last run (or now) using the new interval.
    row = await db.fetchone(
        "SELECT last_run FROM watches WHERE watch_id = ? AND owner_email = ?",
        (watch_id, owner_email),
    )
    base = None
    if row and row.get("last_run"):
        try:
            base = datetime.fromisoformat(row["last_run"])
        except Exception:
            base = None
    base = base or datetime.now(timezone.utc)
    next_run = (base + timedelta(minutes=interval_min)).isoformat()
    await db.execute(
        "UPDATE watches SET interval_min = ?, next_run = ? WHERE watch_id = ? AND owner_email = ?",
        (interval_min, next_run, watch_id, owner_email),
    )
    return {"ok": True, "watch_id": watch_id, "interval_min": interval_min, "next_run": next_run}


async def delete_watch(owner_email: str, watch_id: str) -> dict[str, Any]:
    if not await _owned(owner_email, watch_id):
        raise PermissionError("Watch not found for this account.")
    await db.execute(
        "DELETE FROM watches WHERE watch_id = ? AND owner_email = ?",
        (watch_id, owner_email),
    )
    return {"ok": True, "watch_id": watch_id, "deleted": True}
