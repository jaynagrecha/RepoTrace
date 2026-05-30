import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx


class VirusTotalClient:
    """Small VirusTotal v3 hash reputation client with JSON-file cache.

    RepoTrace only performs hash reputation lookups. It does not upload files and
    does not execute anything. Caching avoids burning VT quota on repeated scans.
    """

    def __init__(self, api_key: str | None = None, timeout: float = 20.0):
        self.api_key = api_key or os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")
        self.timeout = timeout
        self.base = "https://www.virustotal.com/api/v3"
        self.cache_path = Path(os.getenv("VT_CACHE_PATH", "data/vt_cache.json"))
        self.cache_ttl = int(os.getenv("VT_CACHE_TTL_SECONDS", str(7 * 24 * 3600)))
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, Any] | None = None

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _load_cache(self) -> dict[str, Any]:
        if self._cache is not None:
            return self._cache
        try:
            self._cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            self._cache = {}
        return self._cache

    def _save_cache(self) -> None:
        try:
            self.cache_path.write_text(json.dumps(self._cache or {}, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _summarize(self, sha256: str, data: dict[str, Any] | None, status: str = "ok") -> dict[str, Any]:
        if status == "not_configured":
            return {"configured": False, "status": "not_configured", "verdict": "VT key not configured"}
        if status == "not_found":
            return {"configured": True, "status": "not_found", "verdict": "unknown/not in VT", "sha256": sha256}
        if status == "error":
            return {"configured": True, "status": "error", "verdict": "VT lookup error", "sha256": sha256}

        attrs = ((data or {}).get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        timeout = int(stats.get("timeout") or 0)
        if malicious > 0:
            verdict = "malicious"
        elif suspicious > 0:
            verdict = "suspicious"
        elif harmless > 0 or undetected > 0:
            verdict = "clean/undetected"
        else:
            verdict = "no verdict"
        return {
            "configured": True,
            "status": "ok",
            "sha256": sha256,
            "verdict": verdict,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": timeout,
            "last_analysis_date": attrs.get("last_analysis_date"),
            "first_submission_date": attrs.get("first_submission_date"),
            "last_submission_date": attrs.get("last_submission_date"),
            "meaningful_name": attrs.get("meaningful_name"),
            "type_description": attrs.get("type_description"),
            "reputation": attrs.get("reputation"),
            "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    async def lookup_hash(self, sha256: str) -> dict[str, Any]:
        if not self.api_key:
            return self._summarize(sha256, None, "not_configured")

        cache = self._load_cache()
        now = int(time.time())
        cached = cache.get(sha256)
        if cached and now - int(cached.get("cached_at", 0)) < self.cache_ttl:
            result = cached.get("result") or {}
            result["cache_hit"] = True
            return result

        headers = {"x-apikey": self.api_key, "accept": "application/json", "User-Agent": "RepoTrace"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.get(f"{self.base}/files/{sha256}", headers=headers)
            if r.status_code == 404:
                result = self._summarize(sha256, None, "not_found")
            elif r.status_code == 429:
                result = {"configured": True, "status": "rate_limited", "verdict": "VT rate limited", "sha256": sha256}
            elif r.status_code >= 400:
                result = {"configured": True, "status": "error", "verdict": f"VT API error {r.status_code}", "sha256": sha256}
            else:
                result = self._summarize(sha256, r.json(), "ok")
        except Exception as e:
            result = {"configured": True, "status": "error", "verdict": f"VT lookup error: {str(e)[:120]}", "sha256": sha256}

        cache[sha256] = {"cached_at": now, "result": result}
        self._save_cache()
        await asyncio.sleep(float(os.getenv("VT_LOOKUP_DELAY_SECONDS", "0.05")))
        return result
