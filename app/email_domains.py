"""Free / personal email-domain blocklist.

RepoTrace accounts are for organizations: a verified logged-in user gets
unlimited access, while anonymous visitors get the free metered tier. If signups
from free providers were allowed, anyone could register a Gmail and bypass the
pay-per-search model entirely. Registration therefore rejects these domains.

The operator can extend the list at runtime via the FREE_EMAIL_DOMAINS_EXTRA env
var (comma-separated), without a code change.
"""
from __future__ import annotations

import os

# Common free/personal mailbox providers and disposable-mail domains.
FREE_EMAIL_DOMAINS: frozenset[str] = frozenset({
    # Google / Microsoft / Yahoo / Apple
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
    "outlook.in", "live.in",
    "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "ymail.com", "rocketmail.com",
    "icloud.com", "me.com", "mac.com",
    # Privacy / other consumer providers
    "proton.me", "protonmail.com", "pm.me", "tutanota.com", "tuta.io",
    "zoho.com", "zohomail.com", "gmx.com", "gmx.net", "mail.com",
    "aol.com", "yandex.com", "yandex.ru", "fastmail.com", "hey.com",
    "rediffmail.com", "rediff.com",
    # Common disposable/temporary mail
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "throwawaymail.com", "yopmail.com", "trashmail.com",
    "getnada.com", "dispostable.com", "maildrop.cc", "sharklasers.com",
    "moakt.com", "mohmal.com", "fakeinbox.com", "spamgourmet.com",
})


def _extra_domains() -> set[str]:
    raw = os.getenv("FREE_EMAIL_DOMAINS_EXTRA", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def is_free_email_domain(email_or_domain: str) -> bool:
    value = (email_or_domain or "").strip().lower()
    if "@" in value:
        value = value.split("@", 1)[1]
    if not value:
        return False
    return value in FREE_EMAIL_DOMAINS or value in _extra_domains()
