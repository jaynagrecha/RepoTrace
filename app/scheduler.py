"""In-process watch scheduler for RepoTrace v2 (Phase 5).

On the paid Render tier the instance stays warm, so a single background asyncio
task can periodically wake, find watches whose next_run is due, re-run their
snapshot, diff against the stored snapshot, email on changes, and reschedule.

This is intentionally simple (one loop, DB-driven) and safe for a single
instance. If you later scale to multiple instances, move this to a dedicated
worker process or a real scheduler/queue and add row-level claim locking so two
instances don't run the same watch.
"""
from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

from .db import db

_task: asyncio.Task | None = None
_stop = asyncio.Event()


def _tick_seconds() -> int:
    try:
        return max(30, int(os.getenv("SCHEDULER_TICK_SECONDS", "60")))
    except ValueError:
        return 60


def _enabled() -> bool:
    return os.getenv("WATCH_SCHEDULER_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}


async def _run_due_watches() -> None:
    from .analyzer import RepoTraceAnalyzer  # local import avoids cycle at startup
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    due = await db.fetchall(
        "SELECT * FROM watches WHERE enabled = 1 AND (next_run IS NULL OR next_run <= ?) LIMIT 25",
        (now_iso,),
    )
    for w in due:
        watch_id = w["watch_id"]
        interval = int(w.get("interval_min") or 360)
        next_run = (now + timedelta(minutes=interval)).isoformat()
        # Reserve the slot first so a slow run doesn't get re-picked next tick.
        await db.execute("UPDATE watches SET next_run = ?, last_run = ? WHERE watch_id = ?",
                         (next_run, now_iso, watch_id))
        try:
            # Resolve the same token the owner would use in the request path:
            # their org-domain token if configured, else the global GITHUB_TOKEN.
            gh_token = os.getenv("GITHUB_TOKEN")
            owner_email = w.get("owner_email")
            if owner_email:
                try:
                    from .auth import _org_token_for_domain
                    domain = owner_email.split("@", 1)[1] if "@" in owner_email else ""
                    org_token, _ = _org_token_for_domain(domain)
                    if org_token:
                        gh_token = org_token
                except Exception:
                    pass
            analyzer = RepoTraceAnalyzer(github_token=gh_token)
            # watch_target reads the stored snapshot, diffs, emails, and re-saves.
            result = await analyzer.watch_target(
                w["target_input"], target_type=w.get("target_type") or "auto",
                notify_email=w.get("notify_email"), owner_email=w.get("owner_email"),
                interval_min=interval,
            )
            email = (result or {}).get("email", {})
            if email.get("attempted"):
                print(f"[scheduler] watch {watch_id}: email sent={email.get('sent')} "
                      f"{('error='+str(email.get('error'))) if email.get('error') else ''}")
        except Exception as e:
            # Never let one bad watch kill the loop. Log the FULL reason so token
            # / rate-limit / 404 problems are diagnosable.
            await db.execute(
                "UPDATE watches SET last_run = ? WHERE watch_id = ?",
                (now_iso, watch_id),
            )
            print(f"[scheduler] watch {watch_id} failed: {type(e).__name__}: {str(e)[:300]}")


async def _loop() -> None:
    # Small initial delay so startup (DB connect, etc.) settles first.
    await asyncio.sleep(5)
    while not _stop.is_set():
        try:
            await _run_due_watches()
        except Exception as e:  # pragma: no cover
            print(f"[scheduler] tick error: {type(e).__name__}")
        try:
            await asyncio.wait_for(_stop.wait(), timeout=_tick_seconds())
        except asyncio.TimeoutError:
            pass


def start_scheduler() -> None:
    global _task
    if not _enabled():
        print("[scheduler] disabled via WATCH_SCHEDULER_ENABLED")
        return
    if _task and not _task.done():
        return
    _stop.clear()
    _task = asyncio.create_task(_loop())
    print("[scheduler] started")


async def stop_scheduler() -> None:
    global _task
    _stop.set()
    if _task:
        try:
            await asyncio.wait_for(_task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            _task.cancel()
        _task = None
    print("[scheduler] stopped")
