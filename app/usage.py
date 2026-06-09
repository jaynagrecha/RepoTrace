"""DB-backed usage & credit manager for RepoTrace v2.

Key fixes:
* Identity model. Authenticated users are limited and credited by ACCOUNT
  (email). Anonymous callers are limited by trusted IP (see security.client_ip,
  which is not spoofable via leftmost XFF). This stops both the free-search
  bypass and the "someone on my CGNAT IP spent my paid credits" problem.
* Paid credits for logged-in users live on the user row; anonymous credits live
  in anon_credits keyed by IP. A purchase is attributed to whichever identity
  created the order.
* All counters are SQL UPDATEs inside a transaction, removing the JSON
  read-modify-write race.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException, Request

from .db import db
from .security import client_ip, is_admin_request


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "y", "on"}


def today_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def now_ts() -> int:
    return int(time.time())


def _public_static_path(value: str) -> str:
    value = (value or "").strip().replace("\\", "/")
    if not value:
        return ""
    if value.startswith(("http://", "https://", "/static/")):
        return value
    if "app/static/" in value:
        return "/static/" + value.split("app/static/", 1)[1].lstrip("/")
    if value.startswith("static/"):
        return "/" + value
    if "/" not in value:
        return "/static/" + value
    return value


@dataclass
class UsageDecision:
    allowed: bool
    reason: str
    remaining_today: int | None
    used_today: int
    limit_today: int
    public_mode: bool


class UsageManager:
    @property
    def public_mode(self) -> bool:
        return _env_bool("PUBLIC_MODE", False)

    @property
    def free_limit(self) -> int:
        try:
            return max(0, int(os.getenv("FREE_DAILY_LIMIT") or os.getenv("FREE_SEARCHES_PER_DAY", "20")))
        except ValueError:
            return 20

    @property
    def burst_limit(self) -> int:
        try:
            return max(1, int(os.getenv("BURST_LIMIT_PER_MINUTE") or os.getenv("MAX_SEARCHES_PER_MINUTE", "12")))
        except ValueError:
            return 12

    # --- Identity resolution ---------------------------------------------

    async def _identity(self, request: Request) -> tuple[str, Optional[dict]]:
        """Return (identity_key, user_row_or_None).

        identity_key is the user's email when authenticated, else 'ip:<addr>'.
        """
        from .auth import auth_manager  # local import avoids circular dependency
        session = request.headers.get("x-session-token") or request.cookies.get("rt_session")
        user = await auth_manager.user_from_session(session) if session else None
        if user:
            return user["email"], user
        return f"ip:{client_ip(request)}", None

    async def _available_credits(self, identity: str, user: Optional[dict], ip: str) -> int:
        if user:
            return int(user.get("paid_credits") or 0)
        row = await db.fetchone("SELECT credits FROM anon_credits WHERE ip = ?", (ip,))
        return int(row["credits"]) if row else 0

    # --- Status -----------------------------------------------------------

    async def status_for_request(self, request: Request) -> dict[str, Any]:
        identity, user = await self._identity(request)
        ip = client_ip(request)
        day = today_key()
        row = await db.fetchone(
            "SELECT searches FROM usage_daily WHERE identity = ? AND day = ?", (identity, day)
        )
        used = int(row["searches"]) if row else 0
        credits = await self._available_credits(identity, user, ip)
        admin = is_admin_request(request)
        status = {
            "public_mode": self.public_mode,
            "identity": identity if not identity.startswith("ip:") else "anonymous",
            "authenticated": user is not None,
            "date_utc": day,
            "free_searches_per_day": self.free_limit,
            "used_today": used,
            "remaining_today": None if (not self.public_mode or admin) else max(0, self.free_limit - used),
            "paid_credits": credits,
            "rate_limit_per_minute": self.burst_limit,
            "admin_authenticated": admin,
            "access_mode": "admin_unlimited" if admin else ("public_limited" if self.public_mode else "local_unlimited"),
            "payment": self._payment_block(),
        }
        return status

    def _payment_block(self) -> dict[str, Any]:
        key_id = os.getenv("RAZORPAY_KEY_ID", "")
        return {
            "upi_id": os.getenv("UPI_ID", ""),
            "upi_qr_image": _public_static_path(os.getenv("UPI_QR_PATH") or os.getenv("UPI_QR_IMAGE", "")),
            "upi_name": os.getenv("UPI_NAME", "RepoTrace"),
            "price_per_search_inr": os.getenv("PRICE_PER_SEARCH") or os.getenv("PRICE_PER_SEARCH_INR", "2"),
            "dynamic_qr_url": "/api/payment-qr",
            "note": os.getenv("PAYMENT_NOTE", "Pay securely to unlock one extra RepoTrace search."),
            "provider": os.getenv("PAYMENT_PROVIDER", "razorpay"),
            "razorpay_configured": bool(key_id and os.getenv("RAZORPAY_KEY_SECRET")),
            "razorpay_mode": (os.getenv("RAZORPAY_MODE") or ("live" if key_id.startswith("rzp_live_") else "test")),
            "razorpay_webhook_configured": bool(os.getenv("RAZORPAY_WEBHOOK_SECRET")),
        }

    # --- Enforcement ------------------------------------------------------

    async def check(self, request: Request, units: int = 1, endpoint: str = "scan") -> UsageDecision:
        identity, user = await self._identity(request)
        ip = client_ip(request)
        day = today_key()
        now = now_ts()
        limit = self.free_limit

        if is_admin_request(request):
            return UsageDecision(True, "admin_unlimited", None, 0, limit, self.public_mode)

        # Burst check over the last 60s for this identity.
        recent = await db.fetchone(
            "SELECT COUNT(*) AS c FROM usage_events WHERE identity = ? AND ts >= ?",
            (identity, now - 60),
        )
        if int((recent or {}).get("c", 0)) >= self.burst_limit:
            return UsageDecision(False, f"Rate limit hit: max {self.burst_limit} actions/minute.",
                                 None, 0, limit, self.public_mode)

        row = await db.fetchone(
            "SELECT searches FROM usage_daily WHERE identity = ? AND day = ?", (identity, day)
        )
        used = int(row["searches"]) if row else 0

        if self.public_mode and used + units > limit:
            credits = await self._available_credits(identity, user, ip)
            if credits >= units:
                return UsageDecision(True, "paid_credit", 0, used, limit, self.public_mode)
            return UsageDecision(False, "Daily free search limit reached. Purchase credits to continue.",
                                 max(0, limit - used), used, limit, self.public_mode)
        remaining = None if not self.public_mode else max(0, limit - used - units)
        return UsageDecision(True, "allowed", remaining, used, limit, self.public_mode)

    async def record(self, request: Request, units: int = 1, endpoint: str = "scan") -> dict[str, Any]:
        if is_admin_request(request):
            return await self.status_for_request(request)
        identity, user = await self._identity(request)
        ip = client_ip(request)
        day = today_key()
        now = now_ts()
        limit = self.free_limit

        async with db.transaction() as conn:
            cur = await conn.execute(
                "SELECT searches FROM usage_daily WHERE identity = ? AND day = ?", (identity, day)
            )
            r = await cur.fetchone()
            used_before = int(r["searches"]) if r else 0

            # Consume a paid credit when over the free allotment.
            if self.public_mode and used_before + units > limit:
                if user:
                    await conn.execute(
                        "UPDATE users SET paid_credits = MAX(0, paid_credits - ?) WHERE email = ?",
                        (units, identity),
                    )
                else:
                    await conn.execute(
                        """INSERT INTO anon_credits(ip, credits) VALUES(?, 0)
                           ON CONFLICT(ip) DO UPDATE SET credits = MAX(0, credits - ?)""",
                        (ip, units),
                    )

            await conn.execute(
                """INSERT INTO usage_daily(identity, day, searches, units, last_seen)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(identity, day) DO UPDATE SET
                       searches = searches + ?, units = units + ?, last_seen = ?""",
                (identity, day, units, units, now, units, units, now),
            )
            await conn.execute(
                "INSERT INTO usage_events(identity, ts, endpoint, units) VALUES(?,?,?,?)",
                (identity, now, endpoint, units),
            )
            # Trim old burst events opportunistically.
            await conn.execute("DELETE FROM usage_events WHERE ts < ?", (now - 120,))

        return await self.status_for_request(request)

    async def add_paid_credits(self, identity: str, ip: str, units: int = 1,
                               source: str = "payment", order_id: str | None = None,
                               payment_id: str | None = None) -> None:
        units = max(1, int(units or 1))
        async with db.transaction() as conn:
            if identity and not identity.startswith("ip:"):
                await conn.execute(
                    "UPDATE users SET paid_credits = paid_credits + ? WHERE email = ?",
                    (units, identity),
                )
            else:
                await conn.execute(
                    """INSERT INTO anon_credits(ip, credits) VALUES(?, ?)
                       ON CONFLICT(ip) DO UPDATE SET credits = credits + ?""",
                    (ip, units, units),
                )
            await conn.execute(
                """INSERT INTO credit_events(ts, identity, ip, units, source, order_id, payment_id)
                   VALUES(?,?,?,?,?,?,?)""",
                (now_ts(), identity, ip, units, source, order_id, payment_id),
            )

    async def admin_summary(self) -> dict[str, Any]:
        day = today_key()
        today_rows = await db.fetchall(
            "SELECT identity, searches FROM usage_daily WHERE day = ? ORDER BY searches DESC LIMIT 25", (day,)
        )
        total = await db.fetchone("SELECT COALESCE(SUM(searches),0) AS t FROM usage_daily WHERE day = ?", (day,))
        lifetime = await db.fetchone("SELECT COALESCE(SUM(searches),0) AS t FROM usage_daily")
        credit_events = await db.fetchall("SELECT * FROM credit_events ORDER BY ts DESC LIMIT 50")
        return {
            "public_mode": self.public_mode,
            "date_utc": day,
            "total_searches_today": int(total["t"]),
            "active_identities_today": len(today_rows),
            "lifetime_searches": int(lifetime["t"]),
            "free_searches_per_day": self.free_limit,
            "rate_limit_per_minute": self.burst_limit,
            "top_identities_today": today_rows,
            "recent_credit_events": credit_events,
        }


usage_manager = UsageManager()


async def enforce_or_429(request: Request, units: int = 1, endpoint: str = "scan") -> None:
    decision = await usage_manager.check(request, units=units, endpoint=endpoint)
    if not decision.allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "message": decision.reason,
                "used_today": decision.used_today,
                "limit_today": decision.limit_today,
                "remaining_today": decision.remaining_today,
                "public_mode": decision.public_mode,
            },
        )
