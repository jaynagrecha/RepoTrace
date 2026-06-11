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
        from .email_domains import is_free_email_domain
        if is_free_email_domain(email):
            raise ValueError(
                "Please register with your work/organization email. Free email "
                "providers (Gmail, Outlook, Yahoo, etc.) aren't eligible for an "
                "organization account. You can still use RepoTrace without an "
                "account on the free tier."
            )
        if not (org_name or "").strip():
            raise ValueError("Organization name is required to register.")
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
                                     github_token, github_token_fingerprint, email_verified, created_at)
                   VALUES(?,?,?,?,?,?,?,0,?)""",
                (email, domain, (org_name or domain).strip(), salt, _pbkdf(password, salt),
                 (github_token or "").strip(), _token_fingerprint(github_token or ""), _iso(_now())),
            )
        otp_status = await self._issue_otp(email)
        return {
            "ok": True, "email": email, "org_domain": domain,
            "verification_required": True,
            "message": "Account created. Check your email for a 6-digit verification code.",
            "email_sent": otp_status.get("sent", False),
            "_debug_otp": otp_status.get("_debug_code") if os.getenv("DEBUG_OTP") == "1" else None,
        }

    # --- Email OTP verification -----------------------------------------

    async def _issue_otp(self, email: str) -> dict[str, Any]:
        import hashlib as _hashlib
        from .mailer import send_email, smtp_configured
        code = f"{secrets.randbelow(1000000):06d}"
        code_hash = _hashlib.sha256(code.encode()).hexdigest()
        now = _now()
        ttl_min = int(os.getenv("OTP_TTL_MIN", "15"))
        expires = now + timedelta(minutes=ttl_min)
        async with db.transaction() as conn:
            await conn.execute(
                """INSERT INTO email_otps(email, code_hash, created_at, expires_at, attempts, last_sent)
                   VALUES(?,?,?,?,0,?)
                   ON CONFLICT(email) DO UPDATE SET
                       code_hash=excluded.code_hash, created_at=excluded.created_at,
                       expires_at=excluded.expires_at, attempts=0, last_sent=excluded.last_sent""",
                (email, code_hash, _iso(now), _iso(expires), _iso(now)),
            )
        body = (
            f"Your RepoTrace verification code is: {code}\n\n"
            f"It expires in {ttl_min} minutes. Enter it in RepoTrace to activate your account.\n\n"
            "If you didn't create a RepoTrace account, you can ignore this email."
        )
        status = {"sent": False}
        if smtp_configured():
            res = send_email(email, "Verify your RepoTrace account", body)
            status["sent"] = res.get("sent", False)
            status["error"] = res.get("error")
        if os.getenv("DEBUG_OTP") == "1":
            status["_debug_code"] = code
        return status

    async def resend_otp(self, email: str) -> dict[str, Any]:
        email = (email or "").strip().lower()
        user = await db.fetchone("SELECT email_verified FROM users WHERE email = ?", (email,))
        if not user:
            return {"ok": True, "message": "If that account exists and is unverified, a new code was sent."}
        if user.get("email_verified"):
            return {"ok": True, "message": "This account is already verified. Please log in."}
        # Throttle: one resend per 60s.
        existing = await db.fetchone("SELECT last_sent FROM email_otps WHERE email = ?", (email,))
        if existing and existing.get("last_sent"):
            try:
                last = datetime.fromisoformat(existing["last_sent"])
                if (_now() - last).total_seconds() < 60:
                    return {"ok": True, "message": "A code was just sent. Please wait a minute before requesting another."}
            except Exception:
                pass
        st = await self._issue_otp(email)
        return {"ok": True, "message": "A new verification code has been sent.", "email_sent": st.get("sent", False)}

    async def verify_otp(self, email: str, code: str) -> dict[str, Any]:
        import hashlib as _hashlib
        email = (email or "").strip().lower()
        code = (code or "").strip()
        row = await db.fetchone("SELECT * FROM email_otps WHERE email = ?", (email,))
        if not row:
            raise ValueError("No verification code found. Please request a new one.")
        if row.get("expires_at", "") < _iso(_now()):
            raise ValueError("This code has expired. Please request a new one.")
        if int(row.get("attempts") or 0) >= 5:
            raise ValueError("Too many incorrect attempts. Please request a new code.")
        if not hmac.compare_digest(row.get("code_hash") or "", _hashlib.sha256(code.encode()).hexdigest()):
            await db.execute("UPDATE email_otps SET attempts = attempts + 1 WHERE email = ?", (email,))
            raise ValueError("Incorrect code. Please try again.")
        async with db.transaction() as conn:
            await conn.execute("UPDATE users SET email_verified = 1 WHERE email = ?", (email,))
            await conn.execute("DELETE FROM email_otps WHERE email = ?", (email,))
        return {"ok": True, "message": "Email verified. You can now log in."}

    async def login(self, email: str, password: str) -> dict[str, Any]:
        email = (email or "").strip().lower()
        user = await db.fetchone("SELECT * FROM users WHERE email = ?", (email,))
        if not user:
            raise ValueError("Invalid email or password.")
        actual = _pbkdf(password or "", user.get("password_salt") or "")
        if not hmac.compare_digest(user.get("password_hash") or "", actual):
            raise ValueError("Invalid email or password.")
        if not user.get("email_verified"):
            # Surface a distinct, catchable signal so the UI can show the
            # verification prompt and the user falls back to the free tier.
            raise ValueError("EMAIL_NOT_VERIFIED")
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
        user = await db.fetchone("SELECT * FROM users WHERE email = ?", (row["email"],))
        # Unverified accounts are treated as not-logged-in for access purposes,
        # so they fall back to the free anonymous tier.
        if user and not user.get("email_verified"):
            return None
        return user

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

    # --- Password reset --------------------------------------------------

    async def request_password_reset(self, email: str, request_ip: str = "") -> dict[str, Any]:
        """Create a reset token and email a link. Always returns a generic
        success response so the endpoint never reveals whether an email exists.
        """
        import hashlib as _hashlib
        from .mailer import send_email, smtp_configured

        email = (email or "").strip().lower()
        generic = {"ok": True, "message": "If an account exists for that email, a reset link has been sent."}

        # Rate limit: max 3 reset requests per email in the last hour.
        cutoff = _iso(_now() - timedelta(hours=1))
        recent = await db.fetchone(
            "SELECT COUNT(*) AS c FROM password_resets WHERE email = ? AND created_at >= ?",
            (email, cutoff),
        )
        if int((recent or {}).get("c", 0)) >= 3:
            return generic  # silently throttle; do not reveal

        user = await db.fetchone("SELECT email FROM users WHERE email = ?", (email,))
        if not user:
            return generic  # do not reveal non-existence

        raw_token = secrets.token_urlsafe(32)
        token_hash = _hashlib.sha256(raw_token.encode()).hexdigest()
        now = _now()
        ttl_min = int(os.getenv("RESET_TOKEN_TTL_MIN", "30"))
        expires = now + timedelta(minutes=ttl_min)
        async with db.transaction() as conn:
            await conn.execute(
                """INSERT INTO password_resets(token_hash, email, created_at, expires_at, used, request_ip)
                   VALUES(?,?,?,?,0,?)""",
                (token_hash, email, _iso(now), _iso(expires), request_ip),
            )
            await conn.execute("DELETE FROM password_resets WHERE expires_at < ?", (_iso(now),))

        base = os.getenv("APP_BASE_URL", "").rstrip("/")
        link = f"{base}/?reset_token={raw_token}" if base else f"/?reset_token={raw_token}"
        body = (
            "A password reset was requested for your RepoTrace account.\n\n"
            f"Reset your password here (valid for {ttl_min} minutes):\n{link}\n\n"
            "If you did not request this, you can safely ignore this email; your password will not change."
        )
        email_status = {"attempted": False}
        if smtp_configured():
            email_status = send_email(email, "RepoTrace password reset", body)
        out = dict(generic)
        # Surface delivery problems only in non-production to aid testing.
        if os.getenv("DEBUG_RESET") == "1":
            out["_debug"] = {"email": email_status, "link": link}
        return out

    async def confirm_password_reset(self, raw_token: str, new_password: str) -> dict[str, Any]:
        import hashlib as _hashlib
        if not new_password or len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters.")
        token_hash = _hashlib.sha256((raw_token or "").encode()).hexdigest()
        now = _now()
        row = await db.fetchone(
            "SELECT * FROM password_resets WHERE token_hash = ?", (token_hash,)
        )
        if not row or row.get("used") or row.get("expires_at", "") < _iso(now):
            raise ValueError("This reset link is invalid or has expired. Please request a new one.")
        email = row["email"]
        salt = secrets.token_hex(16)
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE users SET password_salt = ?, password_hash = ? WHERE email = ?",
                (salt, _pbkdf(new_password, salt), email),
            )
            await conn.execute("UPDATE password_resets SET used = 1 WHERE token_hash = ?", (token_hash,))
            # Invalidate all existing sessions for this account on password change.
            await conn.execute("DELETE FROM sessions WHERE email = ?", (email,))
        return {"ok": True, "message": "Password updated. You can now log in with your new password."}


auth_manager = AuthManager()
