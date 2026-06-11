"""Resolve GitHub release-asset and mirror URLs back to a canonical owner/repo.

RepoTrace analyzes GitHub/GitLab *repositories*. Several URL forms point at a
release artifact rather than a repo, but each can be traced back to its source
repository:

  1. Canonical release download:
     https://github.com/<owner>/<repo>/releases/download/<tag>/<asset>
       -> owner/repo are in the path (no API call needed).

  2. Official GitHub asset CDN (your case):
     https://release-assets.githubusercontent.com/github-production-release-asset/<repo_id>/<uuid>
       -> <repo_id> resolves to owner/repo via GET /repositories/{id}.

  3. Third-party release mirror (e.g. Astral):
     https://releases.astral.sh/github/<repo>/releases/download/<tag>/<asset>
       -> normalizes to a canonical github.com release URL.

resolve_to_repo_url() returns a plain github.com repo URL (string) that the
existing parse_github_url() already understands, plus provenance metadata so the
UI can show "traced from a release asset".
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse, unquote

# Exact hosts only — never suffix-match githubusercontent.com, or a look-alike
# like release-assets.githubusercontent.com.evil.com would slip through.
GITHUB_ASSET_HOSTS = {"release-assets.githubusercontent.com"}
GITHUB_LEGACY_ASSET_HOSTS = {
    "github-releases.githubusercontent.com",
    "objects.githubusercontent.com",
}
KNOWN_MIRROR_HOSTS = {"releases.astral.sh"}


@dataclass
class ResolvedSource:
    repo_url: str                 # canonical github.com repo URL for the parser
    provenance: str | None = None # human-readable note for the UI
    asset_name: str | None = None
    tag: str | None = None


def _is_release_download_path(parts: list[str]) -> bool:
    # /<owner>/<repo>/releases/download/<tag>/<asset...>
    return len(parts) >= 6 and parts[2] == "releases" and parts[3] == "download"


async def resolve_to_repo_url(url: str, github_client) -> ResolvedSource | None:
    """Return a ResolvedSource if `url` is a release/asset/mirror form, else None.

    `github_client` must expose an async `get(path)` returning parsed JSON (the
    project's GitHubClient). Only used for the repo-ID lookup (case 2).
    """
    u = urlparse(url.strip())
    host = u.netloc.lower()
    parts = [unquote(p) for p in u.path.strip("/").split("/") if p]

    # Case 1: canonical github.com release download URL.
    if host in {"github.com", "www.github.com"} and _is_release_download_path(parts):
        owner, repo = parts[0], parts[1]
        tag = parts[4]
        asset = "/".join(parts[5:])
        return ResolvedSource(
            repo_url=f"https://github.com/{owner}/{repo}",
            provenance=f"Traced from release asset '{asset}' (tag {tag}) of {owner}/{repo}",
            asset_name=asset, tag=tag,
        )

    # Case 2: official GitHub asset CDN — repo ID in the path.
    if host in GITHUB_ASSET_HOSTS | GITHUB_LEGACY_ASSET_HOSTS:
        # .../github-production-release-asset/<repo_id>/<uuid>
        repo_id = None
        for i, p in enumerate(parts):
            if p == "github-production-release-asset" and i + 1 < len(parts):
                repo_id = parts[i + 1]
                break
        if repo_id is None:
            # Some forms put the numeric id as the first path segment.
            for p in parts:
                if p.isdigit():
                    repo_id = p
                    break
        if repo_id and repo_id.isdigit():
            try:
                data = await github_client.get(f"/repositories/{repo_id}")
            except Exception:
                data = None
            if isinstance(data, dict) and data.get("full_name"):
                full = data["full_name"]
                return ResolvedSource(
                    repo_url=f"https://github.com/{full}",
                    provenance=f"Traced from GitHub release-asset CDN (repo id {repo_id}) -> {full}",
                )
            # Couldn't resolve the ID (private/deleted/rate-limited).
            raise ValueError(
                f"This is a GitHub release-asset URL (repo id {repo_id}), but the "
                f"source repository could not be resolved. It may be private, deleted, "
                f"or the API rate limit was hit."
            )
        raise ValueError("Unrecognized GitHub release-asset URL format.")

    # Case 3: known third-party mirror -> normalize to canonical github.com.
    if host in KNOWN_MIRROR_HOSTS:
        # releases.astral.sh/github/<repo>/releases/download/<tag>/<asset>
        if len(parts) >= 2 and parts[0] == "github":
            # Astral hosts a single org's repos; map github/<repo> to astral-sh/<repo>.
            repo = parts[1]
            owner = "astral-sh"
            tag = parts[4] if len(parts) >= 5 and parts[2] == "releases" else None
            return ResolvedSource(
                repo_url=f"https://github.com/{owner}/{repo}",
                provenance=f"Traced from {host} mirror -> {owner}/{repo}"
                           + (f" (tag {tag})" if tag else ""),
                tag=tag,
            )
        raise ValueError(f"Unrecognized mirror URL format for {host}.")

    return None
