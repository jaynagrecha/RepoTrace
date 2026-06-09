"""IOC extraction and secret detection for RepoTrace (v2 engine).

Improvements over the original:

* Domain validation uses a public-suffix approach instead of a hand-maintained
  40-entry TLD allowlist, so real malware infrastructure on TLDs like .top,
  .ru, .su, .cc, .pw, .click, .zip is no longer silently dropped. If the
  optional `publicsuffix2` package is installed it is used for full ICANN
  coverage; otherwise a vendored suffix set (covers the common + abuse-heavy
  TLDs) is used so the module works with no network and no extra dependency.

* Secret detections carry a confidence tier (high/medium/low) and the matched
  pattern name, so downstream risk scoring can weight a high-entropy AWS key
  differently from a generic `password = "..."` assignment that is often a test
  fixture. Each hit also records a redacted preview for analyst triage without
  leaking the full secret into stored reports.

The extractor stays deliberately conservative about what counts as a domain or
IP (URL hosts, email domains, explicit host/ip assignments) to avoid the
classic false positives from code like `document.addEventListener` or
`request.form.get`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# --- Public suffix handling -------------------------------------------------

try:  # Optional, preferred in production for complete ICANN coverage.
    from publicsuffix2 import get_sld, get_tld  # type: ignore

    _HAS_PSL = True
except Exception:  # pragma: no cover - fallback path
    _HAS_PSL = False

# Vendored suffix set: common gTLDs/ccTLDs plus abuse-heavy TLDs that the old
# allowlist omitted. Multi-label suffixes (e.g. co.uk) are listed explicitly.
_VENDORED_SUFFIXES = {
    # generic
    "com", "org", "net", "io", "ai", "dev", "app", "co", "info", "biz", "me",
    "xyz", "site", "online", "cloud", "tech", "security", "software", "systems",
    "digital", "tools", "store", "shop", "live", "world", "today", "news",
    # abuse-heavy / commonly seen in malware C2
    "top", "click", "zip", "mov", "cc", "pw", "su", "tk", "ml", "ga", "cf", "gq",
    "icu", "rest", "fit", "cyou", "sbs", "buzz", "monster", "quest", "link",
    # country
    "us", "uk", "ca", "de", "fr", "jp", "cn", "ru", "au", "br", "za", "sg",
    "nl", "in", "it", "es", "se", "no", "fi", "pl", "ua", "kr", "tr", "ir",
    "gov", "edu", "mil", "int",
    # multi-label
    "co.in", "gov.in", "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au",
    "co.za", "com.br", "co.jp", "com.cn", "ne.jp", "or.jp",
}

_LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")


def _valid_via_vendored(domain: str) -> bool:
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    last = labels[-1]
    last2 = ".".join(labels[-2:])
    return last in _VENDORED_SUFFIXES or last2 in _VENDORED_SUFFIXES


def is_valid_domain(domain: str) -> bool:
    d = (domain or "").strip().strip("`'\"()[]{}<>,.;").lower().rstrip(".")
    if not d or "_" in d or ".." in d or len(d) > 253:
        return False
    labels = d.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or label.startswith("-") or label.endswith("-"):
            return False
        if not _LABEL_RE.match(label):
            return False
    if _HAS_PSL:
        try:
            # A registrable domain has a recognized public suffix and at least
            # one label above it. get_sld returns None for bare/unknown suffixes.
            sld = get_sld(d)
            tld = get_tld(d)
            return bool(sld and tld and sld != tld)
        except Exception:
            pass
    return _valid_via_vendored(d)


# --- Regexes ----------------------------------------------------------------

import ipaddress
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HOST_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:host|hostname|domain|url|uri|endpoint|server|callback|webhook|redirect_uri|base_url)"
    r"\s*[:=]\s*[\"']?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?\"'\s]|$)"
)
IP_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:ip|host|hostname|server|addr|address|endpoint)\s*[:=]\s*[\"']?"
    r"((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?:[/:?\"'\s]|$)"
)


@dataclass
class SecretSignature:
    name: str
    regex: re.Pattern
    confidence: str  # high | medium | low


# Confidence reflects how likely a match is a *real* credential vs a test/sample.
SECRET_SIGNATURES: list[SecretSignature] = [
    SecretSignature("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "high"),
    SecretSignature("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    SecretSignature("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{20,}"), "high"),
    SecretSignature("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high"),
    SecretSignature("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "high"),
    SecretSignature("Generic bearer token", re.compile(r"(?i)bearer\s+[a-z0-9._\-]{20,}"), "medium"),
    SecretSignature(
        "Password/secret assignment",
        re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
        "low",
    ),
]

# Strings that strongly indicate a low-confidence assignment is a placeholder.
_PLACEHOLDER_HINTS = re.compile(
    r"(?i)(example|sample|dummy|placeholder|changeme|change-me|your[_-]?|xxx+|<.*?>|\.\.\.|test|fake|redacted|123456|password123)"
)


def _redact(value: str) -> str:
    """Return a short, non-reversible preview of a secret-bearing line."""
    v = value.strip()
    if len(v) <= 12:
        return v[:2] + "***"
    return f"{v[:4]}…{v[-2:]} (len {len(v)})"


@dataclass
class IOCResult:
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    ipv4: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    secret_hits: list[dict] = field(default_factory=list)  # {name, confidence, preview}

    def to_dict(self) -> dict:
        # secret_pattern_hits kept as a flat name list for backward compatibility
        return {
            "urls": self.urls,
            "emails": self.emails,
            "ipv4": self.ipv4,
            "domains": self.domains,
            "secret_pattern_hits": sorted({h["name"] for h in self.secret_hits}),
            "secret_hits": self.secret_hits,
        }


def _is_public_ipv4(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return obj.version == 4 and not (
        obj.is_private or obj.is_loopback or obj.is_link_local
        or obj.is_multicast or obj.is_reserved or obj.is_unspecified
    )


def _strip(value: str) -> str:
    return value.strip().strip("`'\"()[]{}<>,.;")


# Punctuation that is almost never a meaningful final character of a URL and is
# typically picked up from surrounding markup/prose.
_URL_TRAILING = ".,;:!?\"'`>»”’"


def _clean_url(raw: str) -> str:
    """Trim trailing markup/punctuation from a URL without breaking valid ones.

    Handles the common cases the bare regex over-captures:
      * markdown link tails:  ...x.zip)]   ...x.zip)    [text](url)
      * leading wrapper chars: (https://...   <https://...
      * sentence punctuation:  https://x.com.
    Closing brackets/parens are only stripped when they are unbalanced in the
    captured string, so a legitimate URL like
    en.wikipedia.org/wiki/Foo_(bar) keeps its closing paren.
    """
    u = raw.strip()
    # Strip obvious leading wrappers.
    u = u.lstrip("(<[{`'\"")
    # Iteratively peel trailing characters.
    changed = True
    while changed and u:
        changed = False
        # Plain trailing punctuation.
        if u[-1] in _URL_TRAILING:
            u = u[:-1]
            changed = True
            continue
        # Unbalanced closing bracket/paren -> it belongs to the surrounding text.
        for close, opn in ((")", "("), ("]", "["), ("}", "{")):
            if u.endswith(close) and u.count(close) > u.count(opn):
                u = u[:-1]
                changed = True
                break
    return u


def extract_iocs(text: str, *, cap: int = 500) -> dict:
    """Extract high-confidence IOCs and tiered secret hits from text."""
    urls: list[str] = []
    domains: set[str] = set()
    ipv4: set[str] = set()

    for raw in URL_RE.findall(text):
        u = _clean_url(raw)
        host = (urlparse(u).hostname or "").lower()
        if not host:
            continue
        urls.append(u)
        if _is_public_ipv4(host):
            ipv4.add(host)
        elif is_valid_domain(host):
            domains.add(host)

    emails: list[str] = []
    for raw in EMAIL_RE.findall(text):
        e = _strip(raw)
        domain = e.split("@")[-1].lower() if "@" in e else ""
        if domain in {"users.noreply.github.com", "noreply.github.com"}:
            continue
        emails.append(e)
        if is_valid_domain(domain):
            domains.add(domain)

    for m in HOST_ASSIGNMENT_RE.findall(text):
        d = _strip(m).lower()
        if is_valid_domain(d):
            domains.add(d)

    for m in IP_ASSIGNMENT_RE.findall(text):
        ip = _strip(m)
        if _is_public_ipv4(ip):
            ipv4.add(ip)

    secret_hits: list[dict] = []
    for sig in SECRET_SIGNATURES:
        match = sig.regex.search(text)
        if not match:
            continue
        matched_text = match.group(0)
        confidence = sig.confidence
        # Demote low-confidence assignments that look like placeholders.
        if confidence == "low" and _PLACEHOLDER_HINTS.search(matched_text):
            confidence = "ignore"
        if confidence == "ignore":
            continue
        secret_hits.append({
            "name": sig.name,
            "confidence": confidence,
            "preview": _redact(matched_text),
        })

    return IOCResult(
        urls=sorted(set(urls))[:cap],
        emails=sorted(set(emails))[:cap],
        ipv4=sorted(ipv4)[:cap],
        domains=sorted(domains)[:cap],
        secret_hits=secret_hits,
    ).to_dict()


def empty_iocs() -> dict:
    return IOCResult().to_dict()
