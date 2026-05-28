import asyncio
import os
from typing import Any, Optional
from urllib.parse import quote

import httpx


class GitLabAPIError(Exception):
    pass


class GitLabClient:
    def __init__(self, token: Optional[str] = None, timeout: float = 20.0, retries: int = 2, base_url: str | None = None):
        self.token = token or os.getenv("GITLAB_TOKEN")
        self.base_url = (base_url or os.getenv("GITLAB_BASE_URL") or "https://gitlab.com").rstrip("/")
        self.base = f"{self.base_url}/api/v4"
        self.timeout = timeout
        self.retries = retries
        self.headers = {
            "User-Agent": "RepoTrace-v19",
        }
        if self.token:
            self.headers["PRIVATE-TOKEN"] = self.token

    @staticmethod
    def encode_project_id(project_path: str) -> str:
        return quote(project_path.strip("/"), safe="")

    async def get(self, path_or_url: str, params: Optional[dict[str, Any]] = None, raw_headers: bool = False) -> Any:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base}{path_or_url}"
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    r = await client.get(url, headers=self.headers, params=params)
                if r.status_code == 429:
                    raise GitLabAPIError(f"GitLab rate limit hit: {r.text[:400]}")
                if r.status_code >= 400:
                    raise GitLabAPIError(f"GitLab API error {r.status_code}: {r.text[:500]}")
                data = r.json() if r.content else None
                if raw_headers:
                    return data, dict(r.headers)
                return data
            except Exception as e:
                last_error = e
                if attempt < self.retries:
                    await asyncio.sleep(0.35 * (attempt + 1))
        raise last_error

    async def get_bytes(self, path_or_url: str, params: Optional[dict[str, Any]] = None, max_bytes: int = 1_000_000) -> bytes:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base}{path_or_url}"
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                    r = await client.get(url, headers=self.headers, params=params)
                if r.status_code >= 400:
                    raise GitLabAPIError(f"GitLab raw download error {r.status_code}: {r.text[:300]}")
                return r.content[:max_bytes]
            except Exception as e:
                last_error = e
                if attempt < self.retries:
                    await asyncio.sleep(0.35 * (attempt + 1))
        raise last_error

    async def paginated_get(self, path: str, params: Optional[dict[str, Any]] = None, max_items: int = 500) -> list[dict[str, Any]]:
        params = dict(params or {})
        params["per_page"] = min(100, max_items)
        page, items = 1, []
        while len(items) < max_items:
            params["page"] = page
            batch = await self.get(path, params=params)
            if not isinstance(batch, list) or not batch:
                break
            items.extend(batch)
            if len(batch) < params["per_page"]:
                break
            page += 1
        return items[:max_items]
