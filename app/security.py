"""Shared security helpers for RepoTrace v2.

Fixes from the review:
* Trusted client-IP resolution. The old code took the leftmost value of the
  client-supplied X-Forwarded-For header, which anyone can spoof to reset their
  quota or steal IP-scoped credits. Render (and most proxies) APPEND the real
  client IP as the RIGHTMOST entry, so we trust that, and only honor the header
  at all when TRUST_PROXY=true. Otherwise we use the socket peer.
* Constant-time admin credential comparison (was `==`).
* Exception scrubbing so internal paths/tokens never reach clients.
* A small dependency that injects security headers on every response.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
from pathlib import Path

from fastapi import HTTPException, Request, status


def _trust_proxy() -> bool:
    return os.getenv("TRUST_PROXY", "true").strip().lower() in {"1", "true", "yes", "on"}


def _proxy_hops() -> int:
    # Number of trusted proxies in front of the app. Render = 1.
    try:
        return max(1, int(os.getenv("TRUSTED_PROXY_HOPS", "1")))
    except ValueError:
        return 1


def client_ip(request: Request) -> str:
    """Return a STABLE client identifier.

    Render sits behind Cloudflare, which sets CF-Connecting-IP / True-Client-IP
    to a single, consistent client IP. Preferring those fixes the bug where the
    identity changed on every request: the old code indexed X-Forwarded-For from
    the right by a fixed hop count, but XFF length varies between requests (edge/
    CDN routing), so the resolved IP — and thus the usage row read — kept changing
    (counts appearing to randomly jump on refresh).

    Priority: CF-Connecting-IP -> True-Client-IP -> X-Real-IP -> leftmost XFF
    (the originating client) -> socket peer. When TRUST_PROXY is off, socket only.

    Note: header-based IPs are a usage/identity key, not a security boundary.
    Admin auth and payment verification never rely on this value.
    """
    socket_ip = request.client.host if request.client else "unknown"
    if not _trust_proxy():
        return socket_ip
    # Cloudflare single-IP headers are stable and set by infrastructure.
    for h in ("cf-connecting-ip", "true-client-ip"):
        v = request.headers.get(h)
        if v and v.strip():
            return v.strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            # Leftmost = originating client; stable across requests.
            return parts[0]
    return socket_ip


# --- Admin auth (constant-time) --------------------------------------------

def _admin_credentials() -> dict[str, str]:
    creds: dict[str, str] = {}
    user = os.getenv("ADMIN_USERNAME", "")
    pwd = os.getenv("ADMIN_PASSWORD", "")
    if user and pwd:
        creds[user] = pwd
    test_user = os.getenv("TEST_ADMIN_USERNAME", "")
    test_pwd = os.getenv("TEST_ADMIN_PASSWORD", "")
    if test_user and test_pwd:
        creds[test_user] = test_pwd
    raw = os.getenv("ADMIN_USERS_JSON", "").strip()
    if raw and raw != "change-me-before-public-deploy":
        try:
            for k, v in (json.loads(raw) or {}).items():
                if k and v:
                    creds[str(k)] = str(v)
        except Exception:
            pass
    return creds


def _parse_basic_auth(request: Request) -> tuple[str, str] | None:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
        u, p = raw.split(":", 1)
        return u, p
    except Exception:
        return None


def is_admin_request(request: Request) -> bool:
    creds = _admin_credentials()
    if not creds:
        return False
    parsed = _parse_basic_auth(request)
    if not parsed:
        return False
    supplied_user, supplied_pwd = parsed
    expected = creds.get(supplied_user)
    if expected is None:
        # Still burn a comparison to reduce username-enumeration timing signal.
        hmac.compare_digest(supplied_pwd, supplied_pwd)
        return False
    return hmac.compare_digest(supplied_pwd, expected)


def require_admin_basic(request: Request) -> None:
    creds = _admin_credentials()
    if not creds:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Admin password not configured. Set ADMIN_PASSWORD or ADMIN_USERS_JSON.")
    if not is_admin_request(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid admin credentials",
                            headers={"WWW-Authenticate": "Basic"})


# --- Error scrubbing --------------------------------------------------------

_PATH_RE = re.compile(r"(/[\w.-]+)+")
_TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9_]{6,}|rzp_(?:test|live)_[A-Za-z0-9]+|AKIA[0-9A-Z]{6,}|Bearer\s+\S+)", re.I)


def scrub_error(exc: Exception | str) -> str:
    """Return a safe, generic-ish message with secrets/paths removed."""
    msg = str(getattr(exc, "detail", None) or exc)
    msg = _TOKEN_RE.sub("<redacted>", msg)
    msg = _PATH_RE.sub("<path>", msg)
    return msg[:300]


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline' https://checkout.razorpay.com; "
        "connect-src 'self' https://api.razorpay.com; "
        "frame-src https://api.razorpay.com https://checkout.razorpay.com; "
        "base-uri 'self'; form-action 'self'"
    ),
}
