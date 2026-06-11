"""Shared SMTP mailer for RepoTrace.

Uses the same SMTP_* environment variables already configured for watch alerts,
so password-reset and OTP emails need no new setup. Returns a status dict rather
than raising, so callers can surface a clean message without leaking SMTP detail.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST") and (os.getenv("SMTP_FROM") or os.getenv("SMTP_USERNAME")))


def send_email(to_address: str, subject: str, body: str, *, html: str | None = None) -> dict:
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        return {"attempted": False, "sent": False, "error": "SMTP_HOST is not configured."}
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "").strip()
    sender = (os.getenv("SMTP_FROM") or username).strip()
    if not sender:
        return {"attempted": False, "sent": False, "error": "SMTP_FROM/SMTP_USERNAME is not configured."}
    if not to_address:
        return {"attempted": False, "sent": False, "error": "No recipient address."}

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to_address
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context()) as s:
                if username and password:
                    s.login(username, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=20) as s:
                s.starttls(context=ssl.create_default_context())
                if username and password:
                    s.login(username, password)
                s.send_message(msg)
        return {"attempted": True, "sent": True}
    except Exception as e:
        return {"attempted": True, "sent": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}
