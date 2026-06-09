import asyncio
import os
from typing import Any, Optional

import httpx

from .modules.netsafe import safe_get, assert_url_is_safe, BlockedRequestError


class GitHubAPIError(Exception):
    pass


class GitHubClient:
    def __init__(self, token: Optional[str] = None, timeout: float = 20.0, retries: int = 2):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.base = "https://api.github.com"
        self.timeout = timeout
        self.retries = retries
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "RepoTrace-v2",
        }
        if self.token:
            self.headers["Authorization"] = f"Bearer {self.token}"

    async def get(self, path_or_url: str, params: Optional[dict[str, Any]] = None, raw_headers: bool = False) -> Any:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base}{path_or_url}"
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    r = await safe_get(client, url, headers=self.headers, params=params)
                if r.status_code == 403 and "rate limit" in r.text.lower():
                    raise GitHubAPIError(f"GitHub rate limit hit: {r.text[:300]}")
                if r.status_code >= 400:
                    raise GitHubAPIError(f"GitHub API error {r.status_code}: {r.text[:400]}")
                data = r.json() if r.content else None
                return (data, dict(r.headers)) if raw_headers else data
            except BlockedRequestError as e:
                raise GitHubAPIError(f"Blocked unsafe request: {e}")
            except Exception as e:
                last_error = e
                if attempt < self.retries:
                    await asyncio.sleep(0.35 * (attempt + 1))
        raise last_error

    async def get_bytes(self, url: str, max_bytes: int = 1_000_000) -> bytes:
        headers = {"User-Agent": "RepoTrace-v2"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    r = await safe_get(client, url, headers=headers)
                if r.status_code >= 400:
                    raise GitHubAPIError(f"Raw download error {r.status_code}: {r.text[:200]}")
                return r.content[:max_bytes]
            except BlockedRequestError as e:
                raise GitHubAPIError(f"Blocked unsafe download: {e}")
            except Exception as e:
                last_error = e
                if attempt < self.retries:
                    await asyncio.sleep(0.35 * (attempt + 1))
        raise last_error

    async def rate_limit(self) -> Any:
        return await self.get("/rate_limit")
