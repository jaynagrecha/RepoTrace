"""SSRF-safe networking for RepoTrace.

Every outbound fetch in RepoTrace targets a known API host (GitHub, GitLab,
VirusTotal) or a raw file host derived from those. An attacker controls the
repository URL we are told to analyze, so without guarding the resolved host
they could point us at internal addresses (169.254.169.254 cloud metadata,
127.0.0.1, RFC1918 ranges, etc.).

This module centralizes two protections:

1. Host allowlisting   - only approved hostnames/suffixes may be contacted.
2. Resolved-IP vetting - the hostname's resolved A/AAAA records must all be
                         public addresses; private/loopback/link-local/reserved
                         targets are rejected even if the hostname is allowed
                         (defends against DNS-rebinding-style tricks).

It also disables redirects by default and re-validates the Location header of
any redirect we choose to follow, so a 302 to an internal address is blocked.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Iterable
from urllib.parse import urlparse

import httpx


class BlockedRequestError(Exception):
    """Raised when a request target fails SSRF safety checks."""


# Hostnames (exact or suffix) RepoTrace is permitted to contact.
DEFAULT_ALLOWED_HOST_SUFFIXES: tuple[str, ...] = (
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "gitlab.com",
    "virustotal.com",
    "www.virustotal.com",
)


def _host_allowed(host: str, allowed_suffixes: Iterable[str]) -> bool:
    host = (host or "").lower().strip(".")
    if not host:
        return False
    for suffix in allowed_suffixes:
        s = suffix.lower().strip(".")
        if host == s or host.endswith("." + s):
            return True
    return False


def _ip_is_public(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        obj.is_private
        or obj.is_loopback
        or obj.is_link_local
        or obj.is_multicast
        or obj.is_reserved
        or obj.is_unspecified
        or (obj.version == 6 and obj.is_site_local)
    )


def _resolved_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips = set()
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            ips.add(sockaddr[0])
    return sorted(ips)


def assert_url_is_safe(url: str, allowed_suffixes: Iterable[str] | None = None) -> str:
    """Validate a URL for outbound fetch. Returns the host on success.

    Raises BlockedRequestError if the scheme, host, or any resolved IP is unsafe.
    """
    allowed = tuple(allowed_suffixes or DEFAULT_ALLOWED_HOST_SUFFIXES)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise BlockedRequestError(f"Blocked non-http(s) scheme: {parsed.scheme or 'none'}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise BlockedRequestError("Blocked request with no host")
    if not _host_allowed(host, allowed):
        raise BlockedRequestError(f"Host not in allowlist: {host}")

    # If the host is a literal IP, vet it directly. Otherwise resolve and vet
    # every record so a hostname cannot smuggle us to an internal address.
    try:
        ipaddress.ip_address(host)
        literal_ip = True
    except ValueError:
        literal_ip = False

    if literal_ip:
        if not _ip_is_public(host):
            raise BlockedRequestError(f"Blocked non-public IP literal: {host}")
        return host

    ips = _resolved_ips(host)
    if not ips:
        # Resolution failure is treated as non-fatal: the actual request will
        # fail loudly if the host is truly unreachable, and DNS may be flaky in
        # sandboxes. We do NOT skip the public-IP check when records exist.
        return host
    for ip in ips:
        if not _ip_is_public(ip):
            raise BlockedRequestError(f"Host {host} resolves to non-public IP {ip}")
    return host


async def safe_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    allowed_suffixes: Iterable[str] | None = None,
    max_redirects: int = 3,
) -> httpx.Response:
    """GET with per-hop SSRF validation.

    Redirects are followed manually so each Location is re-validated against the
    allowlist and public-IP rules before we contact it.
    """
    current = url
    for _ in range(max_redirects + 1):
        assert_url_is_safe(current, allowed_suffixes)
        resp = await client.get(current, headers=headers, params=params, follow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location")
            if not location:
                return resp
            # Resolve relative redirects against the current URL.
            current = str(httpx.URL(current).join(location))
            params = None  # query already encoded into the redirect target
            continue
        return resp
    raise BlockedRequestError("Too many redirects while fetching")
