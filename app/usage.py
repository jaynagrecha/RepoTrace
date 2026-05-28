from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request, status

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
USAGE_FILE = DATA_DIR / "usage.json"


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def today_key() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def now_ts() -> int:
    return int(time.time())


def client_ip(request: Request) -> str:
    # Common reverse-proxy headers first; falls back to socket peer.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _public_static_path(value: str) -> str:
    """Convert env QR paths like app/static/upi_qr.png to browser paths like /static/upi_qr.png."""
    value = (value or "").strip().replace("\\", "/")
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://") or value.startswith("/static/"):
        return value
    marker = "app/static/"
    if marker in value:
        return "/static/" + value.split(marker, 1)[1].lstrip("/")
    if value.startswith("static/"):
        return "/" + value
    # Treat a bare filename as a file inside app/static/.
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
    def __init__(self, path: Path = USAGE_FILE):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

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

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"days": {}, "events": []}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {"days": {}, "events": []}

    def save(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(self.path)

    def status_for_ip(self, ip: str) -> dict[str, Any]:
        data = self.load()
        day = today_key()
        entry = data.setdefault("days", {}).setdefault(day, {}).setdefault(ip, {"searches": 0, "units": 0, "last_seen": None})
        used = int(entry.get("searches", 0))
        limit = self.free_limit
        paid_credits = int(data.setdefault("paid_credits", {}).get(ip, 0))
        return {
            "public_mode": self.public_mode,
            "ip": ip,
            "date_utc": day,
            "free_searches_per_day": limit,
            "used_today": used,
            "remaining_today": None if not self.public_mode else max(0, limit - used),
            "paid_credits": paid_credits,
            "rate_limit_per_minute": self.burst_limit,
            "payment": {
                "upi_id": os.getenv("UPI_ID", ""),
                "upi_qr_image": _public_static_path(os.getenv("UPI_QR_PATH") or os.getenv("UPI_QR_IMAGE", "")),
                "upi_name": os.getenv("UPI_NAME", "RepoTrace"),
                "price_per_search_inr": os.getenv("PRICE_PER_SEARCH") or os.getenv("PRICE_PER_SEARCH_INR", "2"),
                "dynamic_qr_url": "/api/payment-qr",
                "upi_deeplink_url": "/api/payment-intent",
                "note": os.getenv("PAYMENT_NOTE", "Pay securely to unlock one extra RepoTrace search."),
                "provider": os.getenv("PAYMENT_PROVIDER", "razorpay"),
                "razorpay_configured": bool(os.getenv("RAZORPAY_KEY_ID") and os.getenv("RAZORPAY_KEY_SECRET")),
                "razorpay_mode": (os.getenv("RAZORPAY_MODE") or ("live" if os.getenv("RAZORPAY_KEY_ID", "").startswith("rzp_live_") else "test")),
                "razorpay_live_mode": (os.getenv("RAZORPAY_MODE", "").lower() == "live") or os.getenv("RAZORPAY_KEY_ID", "").startswith("rzp_live_"),
                "razorpay_webhook_configured": bool(os.getenv("RAZORPAY_WEBHOOK_SECRET")),
                "upi_first": os.getenv("RAZORPAY_UPI_FIRST", "true").lower() in {"1", "true", "yes", "y", "on"},
            },
        }

    def status_for_request(self, request: Request) -> dict[str, Any]:
        ip = client_ip(request)
        status_data = self.status_for_ip(ip)
        if is_admin_request(request):
            status_data["admin_authenticated"] = True
            status_data["remaining_today"] = None
            status_data["access_mode"] = "admin_unlimited"
        else:
            status_data["admin_authenticated"] = False
            status_data["access_mode"] = "public_limited" if self.public_mode else "local_unlimited"
        return status_data

    def check(self, request: Request, units: int = 1, endpoint: str = "scan") -> UsageDecision:
        ip = client_ip(request)
        data = self.load()
        day = today_key()
        now = now_ts()
        days = data.setdefault("days", {})
        by_ip = days.setdefault(day, {}).setdefault(ip, {"searches": 0, "units": 0, "last_seen": None})
        used = int(by_ip.get("searches", 0))
        limit = self.free_limit

        if is_admin_request(request):
            return UsageDecision(True, "admin_unlimited", None, used, limit, self.public_mode)

        # Clean and evaluate rolling one-minute burst events.
        events = data.setdefault("events", [])
        cutoff = now - 60
        events[:] = [e for e in events if int(e.get("ts", 0)) >= cutoff]
        recent = [e for e in events if e.get("ip") == ip]
        if len(recent) >= self.burst_limit:
            return UsageDecision(False, f"Rate limit hit: max {self.burst_limit} scan actions/minute.", max(0, limit-used), used, limit, self.public_mode)

        if self.public_mode and used + units > limit:
            paid_credits = int(data.setdefault("paid_credits", {}).get(ip, 0))
            if paid_credits >= units:
                return UsageDecision(True, "paid_credit", 0, used, limit, self.public_mode)
            return UsageDecision(False, "Daily free search limit reached.", max(0, limit-used), used, limit, self.public_mode)
        return UsageDecision(True, "allowed", None if not self.public_mode else max(0, limit-used-units), used, limit, self.public_mode)

    def record(self, request: Request, units: int = 1, endpoint: str = "scan") -> dict[str, Any]:
        if is_admin_request(request):
            return self.status_for_request(request)
        ip = client_ip(request)
        data = self.load()
        day = today_key()
        now = now_ts()
        by_ip = data.setdefault("days", {}).setdefault(day, {}).setdefault(ip, {"searches": 0, "units": 0, "last_seen": None, "paid_units_used": 0})
        used_before = int(by_ip.get("searches", 0))
        limit = self.free_limit
        if self.public_mode and used_before + units > limit:
            paid = data.setdefault("paid_credits", {})
            available = int(paid.get(ip, 0))
            if available >= units:
                paid[ip] = available - units
                by_ip["paid_units_used"] = int(by_ip.get("paid_units_used", 0)) + units
        by_ip["searches"] = int(by_ip.get("searches", 0)) + units
        by_ip["units"] = int(by_ip.get("units", 0)) + units
        by_ip["last_seen"] = now
        data.setdefault("events", []).append({"ts": now, "ip": ip, "endpoint": endpoint, "units": units})
        self.save(data)
        return self.status_for_ip(ip)

    def add_paid_credits(self, ip: str, units: int = 1, source: str = "payment", order_id: str | None = None, payment_id: str | None = None) -> dict[str, Any]:
        data = self.load()
        paid = data.setdefault("paid_credits", {})
        paid[ip] = int(paid.get(ip, 0)) + max(1, int(units or 1))
        data.setdefault("paid_credit_events", []).append({
            "ts": now_ts(),
            "ip": ip,
            "units": max(1, int(units or 1)),
            "source": source,
            "order_id": order_id,
            "payment_id": payment_id,
        })
        self.save(data)
        return self.status_for_ip(ip)

    def admin_summary(self) -> dict[str, Any]:
        data = self.load()
        day = today_key()
        today = data.get("days", {}).get(day, {})
        total_today = sum(int(v.get("searches", 0)) for v in today.values())
        active_ips_today = len(today)
        all_days = data.get("days", {})
        lifetime = sum(int(v.get("searches", 0)) for d in all_days.values() for v in d.values())
        top_ips = sorted(
            [{"ip": ip, **vals} for ip, vals in today.items()],
            key=lambda x: int(x.get("searches", 0)), reverse=True
        )[:25]
        return {
            "public_mode": self.public_mode,
            "date_utc": day,
            "total_searches_today": total_today,
            "active_ips_today": active_ips_today,
            "lifetime_searches": lifetime,
            "free_searches_per_day": self.free_limit,
            "rate_limit_per_minute": self.burst_limit,
            "top_ips_today": top_ips,
            "payment": self.status_for_ip("admin").get("payment", {}),
            "paid_credits_total": sum(int(v) for v in data.get("paid_credits", {}).values()),
            "paid_credit_events": data.get("paid_credit_events", [])[-50:],
        }


def _parse_basic_auth(request: Request) -> tuple[str, str] | None:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        supplied_user, supplied_pwd = raw.split(":", 1)
        return supplied_user, supplied_pwd
    except Exception:
        return None


def is_admin_request(request: Request) -> bool:
    user = os.getenv("ADMIN_USERNAME", "admin")
    pwd = os.getenv("ADMIN_PASSWORD", "")
    if not pwd:
        return False
    parsed = _parse_basic_auth(request)
    if not parsed:
        return False
    supplied_user, supplied_pwd = parsed
    return supplied_user == user and supplied_pwd == pwd


def require_admin_basic(request: Request) -> None:
    pwd = os.getenv("ADMIN_PASSWORD", "")
    if not pwd:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin password not configured. Set ADMIN_PASSWORD in .env.")
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin auth required", headers={"WWW-Authenticate": "Basic"})
    parsed = _parse_basic_auth(request)
    if not parsed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin auth", headers={"WWW-Authenticate": "Basic"})
    if not is_admin_request(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin credentials", headers={"WWW-Authenticate": "Basic"})


usage_manager = UsageManager()


def enforce_or_429(request: Request, units: int = 1, endpoint: str = "scan") -> None:
    decision = usage_manager.check(request, units=units, endpoint=endpoint)
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
