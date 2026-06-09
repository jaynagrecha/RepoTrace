"""DB-backed authentication for RepoTrace v2.

Changes from the JSON version:
* Users/sessions live in SQLite (durable on the persistent disk).
* Sessions now EXPIRE (default 7 days) and are pruned; the old version kept
  them forever.
* Password verification uses hmac.compare_digest (already did) and all admin
  comparisons are constant-time too (see usage.py).
* Paid credits are an attribute of the user account, not an IP, so a paying
  user keeps their credits across networks and nobody sharing their IP can
  spend them. (Anonymous IP credits are handled separately in usage.py.)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from .db import db

SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", str(7 * 24)))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _pbkdf(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return base64.b64encode(dk).decode()


def _token_fingerprint(token: str) -> str:
    if not token:
        return ""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def _domain_env_key(domain: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in (domain or "").upper()).strip("_")
    return f"ORG_GITHUB_TOKEN_{safe}"


def _org_token_for_domain(domain: str) -> tuple[str, str]:
    domain = (domain or "").strip().lower()
    raw = os.getenv("ORG_GITHUB_TOKENS_JSON", "").strip()
    if raw:
        try:
            mapping = json.loads(raw)
            val = (mapping.get(domain) or mapping.get("*") or "").strip()
            if val:
                return val, f"env-json:{domain if mapping.get(domain) else '*'}"
        except Exception:
            pass
    val = os.getenv(_domain_env_key(domain), "").strip()
    if val:
        return val, f"env:{_domain_env_key(domain)}"
    val = os.getenv("ORG_GITHUB_TOKEN_DEFAULT", "").strip()
    if val:
        return val, "env:ORG_GITHUB_TOKEN_DEFAULT"
    return "", ""


class AuthManager:
    async def register(self, email: str, password: str, github_token: str | None = None,
                       org_name: str | None = None) -> dict[str, Any]:
        email = (email or "").strip().lower()
        if "@" not in email or len(email) < 6:
            raise ValueError("A valid organization/work email is required.")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")
        existing = await db.fetchone("SELECT email FROM users WHERE email = ?", (email,))
        if existing:
            raise ValueError("Account already exists. Please login instead.")
        salt = secrets.token_hex(16)
        domain = email.split("@", 1)[1]
        async with db.transaction() as conn:
            await conn.execute(
                """INSERT INTO users(email, org_domain, org_name, password_salt, password_hash,
                                     github_token, github_token_fingerprint, created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (email, domain, (org_name or domain).strip(), salt, _pbkdf(password, salt),
                 (github_token or "").strip(), _token_fingerprint(github_token or ""), _iso(_now())),
            )
        env_token, _ = _org_token_for_domain(domain)
        return {
            "ok": True, "email": email, "org_domain": domain,
            "github_token_configured": bool(env_token or github_token),
            "token_source": "server_org_env" if env_token else ("legacy_user_token" if github_token else "public_default"),
        }

    async def login(self, email: str, password: str) -> dict[str, Any]:
        email = (email or "").strip().lower()
        user = await db.fetchone("SELECT * FROM users WHERE email = ?", (email,))
        if not user:
            raise ValueError("Invalid email or password.")
        actual = _pbkdf(password or "", user.get("password_salt") or "")
        if not hmac.compare_digest(user.get("password_hash") or "", actual):
            raise ValueError("Invalid email or password.")
        token = secrets.token_urlsafe(32)
        now = _now()
        expires = now + timedelta(hours=SESSION_TTL_HOURS)
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO sessions(token, email, created_at, expires_at) VALUES(?,?,?,?)",
                (token, email, _iso(now), _iso(expires)),
            )
            await conn.execute("UPDATE users SET last_login = ? WHERE email = ?", (_iso(now), email))
            # Opportunistic prune of expired sessions.
            await conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(now),))
        fresh = await db.fetchone("SELECT * FROM users WHERE email = ?", (email,))
        return {"ok": True, "session_token": token, "user": self.public_user(fresh)}

    async def logout(self, session: str) -> dict[str, Any]:
        await db.execute("DELETE FROM sessions WHERE token = ?", (session,))
        return {"ok": True}

    def public_user(self, user: dict[str, Any]) -> dict[str, Any]:
        env_token, _ = _org_token_for_domain(user.get("org_domain") or "")
        legacy = user.get("github_token") or ""
        return {
            "email": user.get("email"),
            "org_domain": user.get("org_domain"),
            "org_name": user.get("org_name"),
            "github_token_configured": bool(env_token or legacy),
            "github_token_source": "server_org_env" if env_token else ("legacy_user_token" if legacy else "public_default"),
            "github_token_fingerprint": _token_fingerprint(env_token or legacy),
            "created_at": user.get("created_at"),
            "last_login": user.get("last_login"),
            "searches": user.get("searches", 0),
            "paid_credits": user.get("paid_credits", 0),
        }

    async def user_from_session(self, session: Optional[str]) -> Optional[dict[str, Any]]:
        if not session:
            return None
        row = await db.fetchone(
            "SELECT * FROM sessions WHERE token = ? AND expires_at >= ?",
            (session, _iso(_now())),
        )
        if not row:
            return None
        return await db.fetchone("SELECT * FROM users WHERE email = ?", (row["email"],))

    async def has_server_org_token(self, session: Optional[str]) -> bool:
        user = await self.user_from_session(session)
        if not user:
            return False
        env_token, _ = _org_token_for_domain(user.get("org_domain") or "")
        return bool(env_token)

    async def user_github_token(self, session: Optional[str]) -> Optional[str]:
        user = await self.user_from_session(session)
        if not user:
            return None
        # Tokens are configured by the operator via environment variables. Use a
        # server-side org token for the user's email domain if set, otherwise the
        # global GITHUB_TOKEN handled by the GitHub client default.
        env_token, _ = _org_token_for_domain(user.get("org_domain") or "")
        return env_token or None

    async def record_user_search(self, session: Optional[str], units: int = 1) -> None:
        user = await self.user_from_session(session)
        if not user:
            return
        await db.execute(
            "UPDATE users SET searches = searches + ? WHERE email = ?",
            (int(units or 1), user["email"]),
        )

    async def status(self, session: Optional[str]) -> dict[str, Any]:
        user = await self.user_from_session(session)
        if not user:
            return {"authenticated": False}
        return {"authenticated": True, "user": self.public_user(user)}


auth_manager = AuthManager()
