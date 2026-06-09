import asyncio
import hashlib
import json
import os
import re
import smtplib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

from .github_client import GitHubClient
from .gitlab_client import GitLabClient
from .vt_client import VirusTotalClient
from .parsers import GitHubTarget, parse_github_url
from .modules.ioc import extract_iocs, empty_iocs
from .modules import risk as risk_engine
from . import storage as storage_module


def _ext(path: str) -> str:
    i = path.rfind(".")
    return path[i:].lower() if i != -1 else ""


PRIORITY_PATHS = (
    ".env", ".npmrc", "config", "settings", "secret", "credential", "token", "auth", "login",
    ".github/workflows", "Dockerfile", "docker-compose", "requirements.txt", "package.json",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "pom.xml", "build.gradle", "go.mod", "go.sum",
    "terraform", "tfvars", "kubernetes", "k8s", "helm", "deploy", "scripts", "install", "setup",
)
INTERESTING_EXTS = {".ps1", ".sh", ".bat", ".cmd", ".js", ".vbs", ".hta", ".py", ".rb", ".php", ".go", ".java", ".ts", ".tsx", ".jsx", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg"}
TEXT_EXTS = INTERESTING_EXTS | {".txt", ".md", ".rst", ".csv", ".xml", ".html", ".css", ".scss", ".lock"}

DIFF_SUSPICIOUS_PATTERNS = {
    "Secret/token introduced": re.compile(r"(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*['\"][^'\"]{6,}['\"]|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}"),
    "Private key block introduced": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Dynamic eval/exec introduced": re.compile(r"(?i)\b(eval|exec)\s*\("),
    "Base64/obfuscation introduced": re.compile(r"(?i)base64|frombase64string|atob\(|btoa\("),
    "Curl/wget pipe to shell introduced": re.compile(r"(?i)(curl|wget).{0,80}\|.{0,40}(bash|sh|powershell|pwsh)"),
    "PowerShell download cradle introduced": re.compile(r"(?i)(invoke-webrequest|iwr|invoke-expression|iex|downloadstring|webclient)"),
}


def hash_bytes(data: bytes) -> dict[str, str]:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest()}


class RepoTraceAnalyzer:
    def __init__(self, github_token: str | None = None):
        self.gh = GitHubClient(token=github_token)
        self.gl = GitLabClient()
        self.vt = VirusTotalClient()

    async def analyze(self, target: GitHubTarget, max_files: int = 120, max_commits: int = 60) -> dict[str, Any]:
        if getattr(target, "platform", "github") == "gitlab":
            return await self.analyze_gitlab(target, max_files=max_files, max_commits=max_commits)
        if target.kind == "user":
            return await self.analyze_user(target.owner)
        return await self.analyze_repo_like(target, max_files=max_files, max_commits=max_commits)


    async def analyze_gitlab(self, target: GitHubTarget, max_files: int = 120, max_commits: int = 60) -> dict[str, Any]:
        """GitLab.com repository intelligence in the same output shape as GitHub analysis."""
        if target.kind == "user" and not target.repo:
            return await self.analyze_gitlab_namespace(target.owner, max_repos=50)

        started = datetime.now(timezone.utc)
        project_path = target.project_path or f"{target.owner}/{target.repo}"
        project_id = self.gl.encode_project_id(project_path)
        project = await self.gl.get(f"/projects/{project_id}")
        branch = target.branch or project.get("default_branch") or "main"

        tree_entries = await self.gl.paginated_get(
            f"/projects/{project_id}/repository/tree",
            params={"recursive": "true", "ref": branch},
            max_items=1500,
        )
        if target.path:
            prefix = target.path.strip("/")
            tree_entries = [e for e in tree_entries if e.get("path") == prefix or e.get("path", "").startswith(prefix + "/")]

        files = [self._gitlab_tree_to_blob(e) for e in tree_entries if e.get("type") == "blob"]
        dirs = [e for e in tree_entries if e.get("type") == "tree"]
        adaptive = self._adaptive_profile(self._gitlab_project_to_repo_meta(project), files, False, max_files, max_commits)
        effective_max_files = min(max_files, adaptive["effective_max_files"])
        effective_max_commits = min(max_commits, adaptive["effective_max_commits"])

        commits = await self.gl.get(
            f"/projects/{project_id}/repository/commits",
            params={"ref_name": branch, "per_page": effective_max_commits},
        )
        selected_files = self._select_files_for_inventory(files, effective_max_files)
        file_results = await self._bounded_gather(
            [lambda f=f: self._analyze_gitlab_file(project_id, project, branch, f, adaptive["max_file_bytes"]) for f in selected_files],
            adaptive["file_concurrency"],
        )
        file_results = await self._enrich_files_with_vt(file_results)
        commit_results = await self._bounded_gather(
            [lambda sha=c.get("id") or c.get("short_id"): self._gitlab_commit_detail(project_id, sha) for c in commits[:effective_max_commits]],
            adaptive["commit_concurrency"],
        )
        aggregate_text = "\n".join(f.get("sample_text", "") for f in file_results if f.get("sample_text"))
        iocs = extract_iocs(aggregate_text)
        repo_meta = self._gitlab_project_to_repo_meta(project)
        infra = self._infra_links(repo_meta, file_results, commit_results, [], iocs)
        suspicious = self._suspicious_findings(file_results, commit_results, iocs, infra)
        risk = self._risk_score(repo_meta, file_results, commit_results, iocs, suspicious, infra)
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        entries = [self._gitlab_tree_to_entry(e) for e in tree_entries]
        perf = {
            "mode": adaptive["mode"], "strategy": "GitLab " + adaptive["strategy"], "repo_size_kb": repo_meta.get("size"),
            "total_files_discovered": len(files), "total_dirs_discovered": len(dirs), "tree_truncated_by_github": False,
            "files_selected_for_scan": len(selected_files), "files_analyzed": len(file_results), "files_hashed": sum(1 for f in file_results if f.get("hashes")), "vt_files_checked": sum(1 for f in file_results if f.get("vt", {}).get("configured")), "commits_selected_for_detail": min(len(commits), effective_max_commits),
            "file_concurrency": adaptive["file_concurrency"], "commit_concurrency": adaptive["commit_concurrency"], "max_file_bytes": adaptive["max_file_bytes"],
            "rate_limit_tip": "GitLab scan: use GITLAB_TOKEN for private/high-volume GitLab API work.", "elapsed_ms": elapsed_ms,
        }
        return {
            "platform": "gitlab", "target_type": target.kind, "snapshot": self._repo_summary(repo_meta), "branch": branch,
            "tree": {"truncated_by_github": False, "total_entries_returned": len(entries), "directories": len(dirs), "files": len(files), "entries": entries[:1500]},
            "adaptive_scan": perf, "languages": {}, "contributors": [], "releases": [],
            "files_analyzed": file_results, "commits": commit_results, "iocs": iocs, "infra_links": infra, "suspicious_findings": suspicious, "risk": risk,
            "limits": {"requested_max_files": max_files, "requested_max_commits": max_commits, "effective_max_files": effective_max_files, "effective_max_commits": effective_max_commits},
        }

    async def analyze_gitlab_namespace(self, namespace: str, max_repos: int = 50) -> dict[str, Any]:
        """Resolve and enrich a GitLab user/group namespace.

        v19.2 intentionally uses multiple public GitLab endpoints because a single
        namespace/project list is too thin for analyst OSINT. Some fields are only
        returned when GitLab exposes them publicly or when GITLAB_TOKEN has access;
        missing values are preserved as None instead of being guessed.
        """
        q = namespace.strip("/")
        projects: list[dict[str, Any]] = []
        source = "fallback_search"
        profile: dict[str, Any] = {
            "login": q,
            "username": q,
            "html_url": f"https://gitlab.com/{q}",
            "type": "namespace",
            "platform": "gitlab",
        }

        # 1) Exact GitLab user lookup: /users?username=<name> then richer /users/:id.
        try:
            users = await self.gl.get("/users", params={"username": q, "per_page": 1})
            if isinstance(users, list) and users:
                u = users[0]
                uid = u.get("id")
                detailed = await self._safe_gitlab_get(f"/users/{uid}", u) if uid else u
                followers = await self._safe_gitlab_count(f"/users/{uid}/followers") if uid else None
                following = await self._safe_gitlab_count(f"/users/{uid}/following") if uid else None
                profile = self._gitlab_user_profile(detailed or u, followers=followers, following=following)
                projects = await self.gl.paginated_get(
                    f"/users/{uid}/projects",
                    params={
                        "order_by": "last_activity_at",
                        "sort": "desc",
                        "simple": "false",
                        "statistics": "true",
                        "with_shared": "false",
                    },
                    max_items=max_repos,
                )
                source = "exact_user"
        except Exception:
            projects = []

        # 2) Exact GitLab group lookup, including subgroup projects.
        if not projects:
            try:
                group_id = self.gl.encode_project_id(q)
                g = await self.gl.get(f"/groups/{group_id}", params={"with_projects": "false"})
                gid = g.get("id")
                profile = self._gitlab_group_profile(g)
                projects = await self.gl.paginated_get(
                    f"/groups/{gid}/projects",
                    params={
                        "include_subgroups": "true",
                        "order_by": "last_activity_at",
                        "sort": "desc",
                        "simple": "false",
                        "statistics": "true",
                    },
                    max_items=max_repos,
                )
                source = "exact_group"
            except Exception:
                projects = []

        # 3) Fallback: search projects and keep only exact namespace matches.
        if not projects:
            try:
                found = await self.gl.paginated_get(
                    "/projects",
                    params={"search": q, "simple": "false", "statistics": "true", "order_by": "last_activity_at", "sort": "desc"},
                    max_items=max_repos * 3,
                )
                ql = q.lower().strip("/")
                projects = [
                    p for p in found
                    if (p.get("path_with_namespace") or "").lower().startswith(ql + "/")
                    or ((p.get("namespace") or {}).get("full_path") or (p.get("namespace") or {}).get("path") or "").lower() == ql
                ][:max_repos]
                profile.update({"type": "namespace/search", "note": "Exact user/group lookup did not return projects; using filtered project search."})
                source = "project_search_filtered"
            except Exception:
                projects = []

        enriched_projects = await self._enrich_gitlab_projects(projects[:max_repos])
        repos = [self._repo_summary(self._gitlab_project_to_repo_meta(p)) for p in enriched_projects]
        profile["public_repos"] = len(repos)
        profile["platform"] = "gitlab"
        profile["total_stars_received"] = sum((r.get("stars") or 0) for r in repos)
        profile["total_forks"] = sum((r.get("forks") or 0) for r in repos)
        profile["last_activity_at"] = self._latest_date([r.get("pushed_at") or r.get("updated_at") for r in repos]) or profile.get("last_activity_at")
        langs = sorted(set(l for r in repos for l in (r.get("languages") or [])))
        profile["languages_observed"] = langs[:40]
        profile["archived_projects"] = sum(1 for r in repos if r.get("archived"))
        profile["public_project_visibility"] = sorted(set(str(r.get("visibility")) for r in repos if r.get("visibility")))

        return {
            "platform": "gitlab",
            "target_type": "user",
            "user": profile,
            "repositories": repos,
            "namespace_scan": {
                "source": source,
                "repos_found": len(repos),
                "note": "GitLab namespace intelligence. Open a specific GitLab project URL for full file/tree/commit/IOC analysis.",
                "enriched_projects": len(enriched_projects),
            },
            "risk": {"score": 0, "level": "INFO", "reasons": ["GitLab namespace intelligence. Select/paste a specific GitLab project URL for deep RepoTrace analysis."]},
        }

    async def _gitlab_get_project_by_id(self, project_id: Any) -> dict[str, Any] | None:
        if project_id is None:
            return None
        return await self._safe_gitlab_get(f"/projects/{project_id}", None, params={"statistics": "true"})

    async def _enrich_gitlab_projects(self, projects: list[dict[str, Any]]) -> list[dict[str, Any]]:
        async def enrich(p: dict[str, Any]) -> dict[str, Any]:
            detailed = await self._gitlab_get_project_by_id(p.get("id")) or p
            languages = await self._safe_gitlab_get(f"/projects/{p.get('id')}/languages", {}) if p.get("id") else {}
            detailed["_repotrace_languages"] = list((languages or {}).keys()) if isinstance(languages, dict) else []
            return detailed
        return await self._bounded_gather([lambda p=p: enrich(p) for p in projects], 5)

    async def _safe_gitlab_count(self, path: str) -> int | None:
        try:
            data = await self.gl.paginated_get(path, params={}, max_items=100)
            return len(data) if isinstance(data, list) else None
        except Exception:
            return None

    @staticmethod
    def _latest_date(values: list[Any]) -> Any:
        vals = [v for v in values if v]
        return sorted(vals)[-1] if vals else None

    def _gitlab_user_profile(self, u: dict[str, Any], followers: int | None = None, following: int | None = None) -> dict[str, Any]:
        return {
            "id": u.get("id"),
            "login": u.get("username"),
            "username": u.get("username"),
            "name": u.get("name"),
            "type": "user",
            "state": u.get("state"),
            "html_url": u.get("web_url"),
            "avatar_url": u.get("avatar_url"),
            "created_at": u.get("created_at"),
            "last_activity_on": u.get("last_activity_on"),
            "bio": u.get("bio"),
            "organization": u.get("organization"),
            "location": u.get("location"),
            "public_email": u.get("public_email"),
            "website_url": u.get("website_url"),
            "linkedin": u.get("linkedin"),
            "twitter": u.get("twitter"),
            "skype": u.get("skype"),
            "private_profile": u.get("private_profile"),
            "followers": followers,
            "following": following,
        }

    def _gitlab_group_profile(self, g: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": g.get("id"),
            "login": g.get("full_path") or g.get("path"),
            "username": g.get("path"),
            "name": g.get("name"),
            "type": "group",
            "html_url": g.get("web_url"),
            "avatar_url": g.get("avatar_url"),
            "created_at": g.get("created_at"),
            "visibility": g.get("visibility"),
            "description": g.get("description"),
            "full_path": g.get("full_path"),
            "parent_id": g.get("parent_id"),
            "project_creation_level": g.get("project_creation_level"),
            "subgroup_creation_level": g.get("subgroup_creation_level"),
            "emails_disabled": g.get("emails_disabled"),
            "lfs_enabled": g.get("lfs_enabled"),
            "request_access_enabled": g.get("request_access_enabled"),
            "wiki_access_level": g.get("wiki_access_level"),
            "duo_features_enabled": g.get("duo_features_enabled"),
        }

    def _gitlab_project_to_repo_meta(self, p: dict[str, Any]) -> dict[str, Any]:
        ns = p.get("namespace") or {}
        owner = ns.get("full_path") or ns.get("path") or (p.get("path_with_namespace", "").split("/")[0] if p.get("path_with_namespace") else None)
        stats = p.get("statistics") if isinstance(p.get("statistics"), dict) else {}
        return {
            "id": p.get("id"),
            "name": p.get("path") or p.get("name"),
            "full_name": p.get("path_with_namespace") or p.get("name_with_namespace"),
            "owner": {"login": owner},
            "html_url": p.get("web_url"),
            "description": p.get("description"),
            "created_at": p.get("created_at"),
            "updated_at": p.get("last_activity_at") or p.get("updated_at"),
            "pushed_at": p.get("last_activity_at"),
            "default_branch": p.get("default_branch"),
            "size": (stats.get("repository_size") or 0) // 1024,
            "storage_size_kb": (stats.get("storage_size") or 0) // 1024,
            "commit_count": stats.get("commit_count"),
            "stargazers_count": p.get("star_count"),
            "forks_count": p.get("forks_count"),
            "watchers_count": None,
            "open_issues_count": p.get("open_issues_count"),
            "license": None,
            "topics": p.get("topics") or p.get("tag_list") or [],
            "fork": bool(p.get("forked_from_project")),
            "archived": p.get("archived"),
            "disabled": False,
            "visibility": p.get("visibility"),
            "namespace_full_path": ns.get("full_path"),
            "namespace_kind": ns.get("kind"),
            "readme_url": p.get("readme_url"),
            "ssh_url_to_repo": p.get("ssh_url_to_repo"),
            "http_url_to_repo": p.get("http_url_to_repo"),
            "web_url": p.get("web_url"),
            "issues_enabled": p.get("issues_enabled"),
            "merge_requests_enabled": p.get("merge_requests_enabled"),
            "wiki_enabled": p.get("wiki_enabled"),
            "jobs_enabled": p.get("jobs_enabled"),
            "snippets_enabled": p.get("snippets_enabled"),
            "container_registry_enabled": p.get("container_registry_enabled"),
            "packages_enabled": p.get("packages_enabled"),
            "shared_runners_enabled": p.get("shared_runners_enabled"),
            "lfs_enabled": p.get("lfs_enabled"),
            "request_access_enabled": p.get("request_access_enabled"),
            "empty_repo": p.get("empty_repo"),
            "import_status": p.get("import_status"),
            "creator_id": p.get("creator_id"),
            "last_activity_at": p.get("last_activity_at"),
            "languages": p.get("_repotrace_languages") or [],
        }

    def _gitlab_tree_to_blob(self, e: dict[str, Any]) -> dict[str, Any]:
        return {"path": e.get("path"), "type": "blob", "sha": e.get("id"), "size": e.get("size") or 0}

    def _gitlab_tree_to_entry(self, e: dict[str, Any]) -> dict[str, Any]:
        typ = "blob" if e.get("type") == "blob" else "tree"
        return {"path": e.get("path"), "type": typ, "sha": e.get("id"), "size": e.get("size") or 0}

    async def _analyze_gitlab_file(self, project_id: str, project: dict[str, Any], branch: str, item: dict[str, Any], max_bytes: int) -> dict[str, Any]:
        from urllib.parse import quote
        path = item.get("path", "")
        encoded_path = quote(path, safe="")
        web_url = f"{project.get('web_url')}/-/blob/{branch}/{path}"
        raw_url = f"{project.get('web_url')}/-/raw/{branch}/{path}"
        size = item.get("size") or 0
        result = {"path": path, "size": size, "git_blob_sha": item.get("sha"), "raw_download_url": raw_url, "html_url": web_url, "priority": self._file_priority(path, size)}
        if size > max_bytes:
            result["hash_note"] = f"Skipped hashing because file is over safety limit ({max_bytes} bytes). Increase MAX_FILE_HASH_BYTES if needed."
            return result
        data = await self.gl.get_bytes(f"/projects/{project_id}/repository/files/{encoded_path}/raw", params={"ref": branch}, max_bytes=max_bytes)
        result["byte_count"] = len(data)
        result["hashes"] = hash_bytes(data)
        if self._should_text_scan(path, data):
            text = data.decode("utf-8", errors="ignore")
            result["iocs"] = extract_iocs(text)
            result["sample_text"] = text[:25000]
            result["content_type_guess"] = "text"
        else:
            result["iocs"] = empty_iocs()
            result["content_type_guess"] = "binary/non-text"
        return result

    async def _gitlab_commit_detail(self, project_id: str, sha: str | None) -> dict[str, Any]:
        if not sha:
            return {}
        c = await self.gl.get(f"/projects/{project_id}/repository/commits/{sha}")
        diffs = await self._safe_gitlab_get(f"/projects/{project_id}/repository/commits/{sha}/diff", [])
        return {
            "sha": c.get("id"), "html_url": c.get("web_url"), "message": c.get("message") or c.get("title"),
            "author_name": c.get("author_name"), "author_email": c.get("author_email"), "author_date": c.get("authored_date"),
            "committer_name": c.get("committer_name"), "committer_email": c.get("committer_email"), "committer_date": c.get("committed_date"),
            "verified": None, "verification_reason": "gitlab", "stats": c.get("stats"),
            "files": [{"filename": d.get("new_path") or d.get("old_path"), "status": "renamed" if d.get("renamed_file") else "deleted" if d.get("deleted_file") else "new" if d.get("new_file") else "modified", "additions": None, "deletions": None, "changes": None, "raw_url": None, "patch": (d.get("diff") or "")[:5000]} for d in (diffs or [])[:80]],
        }

    async def _safe_gitlab_get(self, path: str, default: Any, params: dict | None = None) -> Any:
        try:
            return await self.gl.get(path, params=params)
        except Exception:
            return default

    async def analyze_user(self, username: str) -> dict[str, Any]:
        user, repos = await asyncio.gather(
            self.gh.get(f"/users/{username}"),
            self.gh.get(f"/users/{username}/repos", params={"per_page": 100, "sort": "updated"}),
        )
        return {"target_type": "user", "user": user, "repositories": [self._repo_summary(r) for r in repos], "risk": {"score": 0, "level": "INFO", "reasons": ["User-level scan only. Repo scans calculate file/change risk."]}}

    async def analyze_repo_like(self, target: GitHubTarget, max_files: int, max_commits: int) -> dict[str, Any]:
        owner, repo = target.owner, target.repo
        started = datetime.now(timezone.utc)
        repo_meta = await self.gh.get(f"/repos/{owner}/{repo}")
        branch = target.branch or repo_meta.get("default_branch")
        branch_obj = await self.gh.get(f"/repos/{owner}/{repo}/branches/{branch}")
        tree_sha = branch_obj["commit"]["commit"]["tree"]["sha"]
        tree = await self.gh.get(f"/repos/{owner}/{repo}/git/trees/{tree_sha}", params={"recursive": "1"})
        entries = tree.get("tree", [])
        if target.path:
            prefix = target.path.strip("/")
            entries = [e for e in entries if e.get("path") == prefix or e.get("path", "").startswith(prefix + "/")]
        files = [e for e in entries if e.get("type") == "blob"]
        dirs = [e for e in entries if e.get("type") == "tree"]
        adaptive = self._adaptive_profile(repo_meta, files, tree.get("truncated", False), max_files, max_commits)
        effective_max_files = min(max_files, adaptive["effective_max_files"])
        effective_max_commits = min(max_commits, adaptive["effective_max_commits"])

        languages_t = self._safe_get(f"/repos/{owner}/{repo}/languages", {})
        contributors_t = self._safe_get(f"/repos/{owner}/{repo}/contributors", [], params={"per_page": 30})
        releases_t = self._safe_get(f"/repos/{owner}/{repo}/releases", [], params={"per_page": 20})
        commits_t = self._safe_get(f"/repos/{owner}/{repo}/commits", [], params={"per_page": effective_max_commits, "sha": branch})
        owner_t = self._safe_get(f"/users/{owner}", {})
        languages, contributors, releases, commits, owner_profile = await asyncio.gather(
            languages_t, contributors_t, releases_t, commits_t, owner_t)
        # Surface the owner account's GitHub join date onto the repo meta so the
        # snapshot can show how old the hosting account is (a new account hosting
        # payloads is a useful triage signal).
        if isinstance(owner_profile, dict) and owner_profile.get("created_at"):
            repo_meta["owner_created_at"] = owner_profile.get("created_at")
            repo_meta["owner_type"] = owner_profile.get("type")

        selected_files = self._select_files_for_inventory(files, effective_max_files)
        file_results = await self._bounded_gather([lambda f=f: self._analyze_file(owner, repo, branch, f, adaptive["max_file_bytes"]) for f in selected_files], adaptive["file_concurrency"])
        file_results = await self._enrich_files_with_vt(file_results)
        commit_results = await self._bounded_gather([lambda sha=c.get("sha"): self._commit_detail(owner, repo, sha) for c in commits[:effective_max_commits]], adaptive["commit_concurrency"])

        aggregate_text = "\n".join(f.get("sample_text", "") for f in file_results if f.get("sample_text"))
        iocs = extract_iocs(aggregate_text)
        infra = self._infra_links(repo_meta, file_results, commit_results, contributors, iocs)
        suspicious = self._suspicious_findings(file_results, commit_results, iocs, infra)
        risk = self._risk_score(repo_meta, file_results, commit_results, iocs, suspicious, infra)
        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
        perf = {
            "mode": adaptive["mode"], "strategy": adaptive["strategy"], "repo_size_kb": repo_meta.get("size"),
            "total_files_discovered": len(files), "total_dirs_discovered": len(dirs), "tree_truncated_by_github": tree.get("truncated", False),
            "files_selected_for_scan": len(selected_files), "files_analyzed": len(file_results), "files_hashed": sum(1 for f in file_results if f.get("hashes")), "vt_files_checked": sum(1 for f in file_results if f.get("vt", {}).get("configured")), "commits_selected_for_detail": min(len(commits), effective_max_commits),
            "file_concurrency": adaptive["file_concurrency"], "commit_concurrency": adaptive["commit_concurrency"], "max_file_bytes": adaptive["max_file_bytes"],
            "rate_limit_tip": adaptive["rate_limit_tip"], "elapsed_ms": elapsed_ms,
        }
        return {
            "target_type": target.kind, "snapshot": self._repo_summary(repo_meta), "branch": branch,
            "tree": {"truncated_by_github": tree.get("truncated", False), "total_entries_returned": len(entries), "directories": len(dirs), "files": len(files), "entries": entries[:1500]},
            "adaptive_scan": perf, "languages": languages, "contributors": contributors, "releases": [self._release_summary(r) for r in releases],
            "files_analyzed": file_results, "commits": commit_results, "iocs": iocs, "infra_links": infra, "suspicious_findings": suspicious, "risk": risk,
            "limits": {"requested_max_files": max_files, "requested_max_commits": max_commits, "effective_max_files": effective_max_files, "effective_max_commits": effective_max_commits},
        }

    async def bulk_scan(self, urls: list[str], max_files: int = 80, max_commits: int = 35, concurrency: int = 3) -> dict[str, Any]:
        sem = asyncio.Semaphore(max(1, min(concurrency, 6)))
        async def one(url: str) -> dict[str, Any]:
            async with sem:
                try:
                    target = parse_github_url(url)
                    result = await self.analyze(target, max_files=max_files, max_commits=max_commits)
                    return {"url": url, "ok": True, "summary": self._bulk_summary(result), "result": result}
                except Exception as e:
                    return {"url": url, "ok": False, "error": str(e)}
        results = await asyncio.gather(*(one(u.strip()) for u in urls if u.strip()))
        ok_results = [r for r in results if r.get("ok")]
        cross_repo = self._cross_repo_links([r["result"] for r in ok_results])
        return {
            "count": len(results),
            "ok": len(ok_results),
            "failed": len(results) - len(ok_results),
            "results": results,
            "cross_repo": cross_repo,
            "graph": self._infra_graph_from_cross_repo(cross_repo),
        }

    async def scan_account(self, account: str, account_type: str = "auto", max_repos: int = 50, max_files: int = 60, max_commits: int = 25, concurrency: int = 3) -> dict[str, Any]:
        """Scan all/selected public repositories for a GitHub user or organization."""
        account = account.strip().strip("/")
        if not account:
            raise ValueError("Account/user/org is required")

        resolved_type = account_type
        profile = None
        if account_type in ("auto", "user"):
            try:
                profile = await self.gh.get(f"/users/{account}")
                resolved_type = "user" if profile.get("type", "").lower() != "organization" else "org"
            except Exception:
                if account_type == "user":
                    raise
        if account_type == "org" or (account_type == "auto" and profile is None):
            profile = await self.gh.get(f"/orgs/{account}")
            resolved_type = "org"

        endpoint = f"/orgs/{account}/repos" if resolved_type == "org" else f"/users/{account}/repos"
        repos = await self._paginate(endpoint, params={"sort": "updated", "direction": "desc", "type": "public"}, max_items=max_repos)

        sem = asyncio.Semaphore(max(1, min(concurrency, 6)))

        async def scan_repo(repo_obj: dict[str, Any]) -> dict[str, Any]:
            async with sem:
                try:
                    target = GitHubTarget(kind="repo", owner=repo_obj.get("owner", {}).get("login") or account, repo=repo_obj.get("name"))
                    result = await self.analyze(target, max_files=max_files, max_commits=max_commits)
                    return {"ok": True, "summary": self._bulk_summary(result), "result": result}
                except Exception as e:
                    return {"ok": False, "repo": repo_obj.get("full_name"), "error": str(e), "summary": self._repo_summary(repo_obj)}

        scanned = await asyncio.gather(*(scan_repo(r) for r in repos))
        ok_results = [r for r in scanned if r.get("ok")]
        cross_repo = self._cross_repo_links([r["result"] for r in ok_results])

        risk_ranked = sorted(
            [r["summary"] for r in ok_results],
            key=lambda x: (x.get("risk_score") or 0, x.get("stars") or 0),
            reverse=True,
        )

        return {
            "target_type": "account_scan",
            "account": account,
            "account_type": resolved_type,
            "profile": profile,
            "repo_count_returned": len(repos),
            "repo_count_scanned": len(scanned),
            "ok": len(ok_results),
            "failed": len(scanned) - len(ok_results),
            "risk_ranked": risk_ranked,
            "results": scanned,
            "cross_repo": cross_repo,
            "graph": self._infra_graph_from_cross_repo(cross_repo),
            "summary": self._account_scan_summary(profile, repos, ok_results, cross_repo),
        }

    async def watch_target(self, target_input: str, target_type: str = "auto", notify_email: str | None = None, max_repos: int = 50, max_files: int = 70, max_commits: int = 30, concurrency: int = 3, owner_email: str | None = None, interval_min: int = 360) -> dict[str, Any]:
        """Advanced watch mode: compare current repo/user/org intelligence with last snapshot.

        v2: snapshots persist in the `watches` table (durable on the Render disk),
        so the background scheduler (Phase 5) can re-run watches and the previous
        snapshot survives restarts.
        """
        from .db import db
        target_input = target_input.strip()
        if not target_input:
            raise ValueError("Watch target is required")

        current = await self._build_watch_snapshot(target_input, target_type, max_repos, max_files, max_commits, concurrency)
        watch_id = self._watch_id(current["target_key"])

        row = await db.fetchone("SELECT snapshot FROM watches WHERE watch_id = ?", (watch_id,))
        previous = None
        if row and row.get("snapshot"):
            try:
                previous = json.loads(row["snapshot"])
            except Exception:
                previous = None

        diff = self._diff_watch_snapshots(previous, current)
        now = datetime.now(timezone.utc)
        next_run = now.replace(microsecond=0).isoformat()
        async with db.transaction() as conn:
            await conn.execute(
                """INSERT INTO watches(watch_id, owner_email, target_input, target_type, notify_email,
                                       enabled, interval_min, snapshot, last_run, next_run, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(watch_id) DO UPDATE SET
                       owner_email=excluded.owner_email, notify_email=excluded.notify_email,
                       target_type=excluded.target_type, interval_min=excluded.interval_min,
                       snapshot=excluded.snapshot, last_run=excluded.last_run""",
                (watch_id, owner_email, target_input, target_type, notify_email,
                 1, int(interval_min), json.dumps(current, ensure_ascii=False),
                 now.isoformat(), next_run, now.isoformat()),
            )

        email_status = {"attempted": False, "sent": False}
        recipient = notify_email or os.getenv("WATCH_EMAIL_TO")
        if previous and diff.get("has_changes") and recipient:
            email_status = self._send_watch_email(recipient, current, diff)

        return {
            "watch_id": watch_id,
            "first_scan": previous is None,
            "previous_snapshot_found": previous is not None,
            "current": current,
            "diff": diff,
            "email": email_status,
            "snapshot_saved_to": f"db:watches/{watch_id}",
        }

    async def _build_watch_snapshot(self, target_input: str, target_type: str, max_repos: int, max_files: int, max_commits: int, concurrency: int) -> dict[str, Any]:
        created = datetime.now(timezone.utc).isoformat()
        if ("github.com/" in target_input or "gitlab.com/" in target_input) and "/" in target_input.split(".com/", 1)[-1]:
            target = parse_github_url(target_input)
            result = await self.analyze(target, max_files=max_files, max_commits=max_commits)
            return self._snapshot_from_repo_result(result, created)

        account = target_input.strip().strip("/")
        scan = await self.scan_account(account, account_type=target_type, max_repos=max_repos, max_files=max_files, max_commits=max_commits, concurrency=concurrency)
        repos = {}
        for r in scan.get("results", []):
            if r.get("ok"):
                repo_snap = self._snapshot_from_repo_result(r["result"], created)
                repos[repo_snap["target_key"]] = repo_snap
        return {
            "schema": "repotrace-watch-v1",
            "target_kind": "account",
            "target_key": f"{scan.get('account_type')}:{account}",
            "display_name": account,
            "created_at": created,
            "profile": {
                "login": (scan.get("profile") or {}).get("login"),
                "created_at": (scan.get("profile") or {}).get("created_at"),
                "updated_at": (scan.get("profile") or {}).get("updated_at"),
                "public_repos": (scan.get("profile") or {}).get("public_repos"),
                "html_url": (scan.get("profile") or {}).get("html_url"),
            },
            "repos": repos,
            "repo_keys": sorted(repos.keys()),
            "domains": sorted(set().union(*(set(v.get("domains", [])) for v in repos.values()))) if repos else [],
            "ipv4": sorted(set().union(*(set(v.get("ipv4", [])) for v in repos.values()))) if repos else [],
            "risk": scan.get("summary", {}),
        }

    def _snapshot_from_repo_result(self, result: dict[str, Any], created: str) -> dict[str, Any]:
        s = result.get("snapshot", {})
        tree_entries = result.get("tree", {}).get("entries", [])
        file_paths = sorted(e.get("path") for e in tree_entries if e.get("type") == "blob" and e.get("path"))
        file_hashes = {
            e.get("path"): (e.get("sha") or e.get("id") or e.get("oid"))
            for e in tree_entries
            if e.get("type") == "blob" and e.get("path") and (e.get("sha") or e.get("id") or e.get("oid"))
        }
        commit_details = []
        for c in result.get("commits", []):
            sha = c.get("sha")
            if not sha:
                continue
            commit = c.get("commit", {}) or {}
            author = commit.get("author", {}) or {}
            commit_details.append({
                "sha": sha,
                "short_sha": sha[:7],
                "date": author.get("date") or c.get("date"),
                "author": author.get("name") or c.get("author_name") or c.get("author"),
                "message": (commit.get("message") or c.get("message") or "").split("\n")[0][:220],
                "url": c.get("html_url") or c.get("web_url"),
            })
        commit_shas = [c.get("sha") for c in commit_details if c.get("sha")]
        iocs = result.get("iocs", {}) or {}
        return {
            "schema": "repotrace-watch-v1",
            "target_kind": "repo",
            "target_key": f"repo:{s.get('full_name')}",
            "display_name": s.get("full_name"),
            "created_at": created,
            "repo": {
                "owner": s.get("owner"),
                "name": s.get("name"),
                "full_name": s.get("full_name"),
                "html_url": s.get("html_url"),
                "created_at": s.get("created_at"),
                "updated_at": s.get("updated_at"),
                "pushed_at": s.get("pushed_at"),
                "default_branch": s.get("default_branch"),
            },
            "file_paths": file_paths,
            "file_count": len(file_paths),
            "file_hashes": file_hashes,
            "commit_shas": commit_shas,
            "commit_details": commit_details[:200],
            "latest_commit": commit_shas[0] if commit_shas else None,
            "domains": sorted(set(iocs.get("domains", []))),
            "ipv4": sorted(set(iocs.get("ipv4", []))),
            "urls": sorted(set(iocs.get("urls", [])))[:300],
            "risk": result.get("risk", {}),
            "suspicious_findings": result.get("suspicious_findings", [])[:100],
        }

    def _diff_watch_snapshots(self, previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, Any]:
        if not previous:
            return {"has_changes": False, "summary": ["Baseline snapshot created. Run watch again later to detect changes."], "new_commits": [], "new_commit_details": [], "new_files": [], "deleted_files": [], "modified_files": [], "new_domains": [], "new_ipv4": [], "risk_changes": []}
        if current.get("target_kind") == "account":
            return self._diff_account_snapshots(previous, current)
        return self._diff_repo_snapshots(previous, current)

    def _diff_repo_snapshots(self, previous: dict[str, Any], current: dict[str, Any], prefix: str = "") -> dict[str, Any]:
        old_files, new_files_set = set(previous.get("file_paths", [])), set(current.get("file_paths", []))
        old_hashes, new_hashes = previous.get("file_hashes", {}) or {}, current.get("file_hashes", {}) or {}
        modified_files = sorted(p for p in (old_files & new_files_set) if old_hashes.get(p) and new_hashes.get(p) and old_hashes.get(p) != new_hashes.get(p))
        old_commits, new_commits_set = set(previous.get("commit_shas", [])), set(current.get("commit_shas", []))
        old_domains, new_domains_set = set(previous.get("domains", [])), set(current.get("domains", []))
        old_ipv4, new_ipv4_set = set(previous.get("ipv4", [])), set(current.get("ipv4", []))
        new_commit_set = new_commits_set - old_commits
        new_commit_details = [c for c in current.get("commit_details", []) if c.get("sha") in new_commit_set]
        risk_changes = []
        old_risk, new_risk = previous.get("risk", {}) or {}, current.get("risk", {}) or {}
        if old_risk.get("level") != new_risk.get("level") or old_risk.get("score") != new_risk.get("score"):
            risk_changes.append({"target": prefix or current.get("display_name"), "from": old_risk, "to": new_risk})
        diff = {
            "has_changes": False,
            "summary": [],
            "new_commits": sorted(new_commit_set),
            "new_commit_details": new_commit_details[:80],
            "new_files": sorted(new_files_set - old_files),
            "deleted_files": sorted(old_files - new_files_set),
            "modified_files": modified_files,
            "new_domains": sorted(new_domains_set - old_domains),
            "new_ipv4": sorted(new_ipv4_set - old_ipv4),
            "risk_changes": risk_changes,
        }
        diff["has_changes"] = any(diff[k] for k in ("new_commits", "new_files", "deleted_files", "modified_files", "new_domains", "new_ipv4", "risk_changes"))
        if diff["new_commits"]: diff["summary"].append(f"{len(diff['new_commits'])} new commit(s)")
        if diff["new_files"]: diff["summary"].append(f"{len(diff['new_files'])} new file(s)")
        if diff["deleted_files"]: diff["summary"].append(f"{len(diff['deleted_files'])} deleted file(s)")
        if diff["modified_files"]: diff["summary"].append(f"{len(diff['modified_files'])} modified file(s)")
        if diff["new_domains"]: diff["summary"].append(f"{len(diff['new_domains'])} new domain(s)")
        if diff["new_ipv4"]: diff["summary"].append(f"{len(diff['new_ipv4'])} new public IP(s)")
        if diff["risk_changes"]: diff["summary"].append(f"{len(diff['risk_changes'])} risk change(s)")
        if not diff["summary"]: diff["summary"].append("No changes detected since previous scan.")
        return diff

    def _diff_account_snapshots(self, previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
        old_repos, new_repos = previous.get("repos", {}) or {}, current.get("repos", {}) or {}
        old_keys, new_keys = set(old_repos), set(new_repos)
        repo_diffs = {}
        combined = {"has_changes": False, "summary": [], "new_repos": sorted(new_keys - old_keys), "deleted_repos": sorted(old_keys - new_keys), "repo_diffs": repo_diffs, "new_commits": [], "new_files": [], "deleted_files": [], "modified_files": [], "new_domains": [], "new_ipv4": [], "risk_changes": []}
        for key in sorted(old_keys & new_keys):
            d = self._diff_repo_snapshots(old_repos[key], new_repos[key], prefix=key)
            if d.get("has_changes"):
                repo_diffs[key] = d
                combined["new_commits"].extend([{"repo": key, "sha": x} for x in d.get("new_commits", [])])
                combined["new_files"].extend([{"repo": key, "path": x} for x in d.get("new_files", [])])
                combined["deleted_files"].extend([{"repo": key, "path": x} for x in d.get("deleted_files", [])])
                combined["modified_files"].extend([{"repo": key, "path": x} for x in d.get("modified_files", [])])
                combined["new_domains"].extend(d.get("new_domains", []))
                combined["new_ipv4"].extend(d.get("new_ipv4", []))
                combined["risk_changes"].extend(d.get("risk_changes", []))
        combined["new_domains"] = sorted(set(combined["new_domains"]))
        combined["new_ipv4"] = sorted(set(combined["new_ipv4"]))
        combined["has_changes"] = bool(combined["new_repos"] or combined["deleted_repos"] or repo_diffs or combined["new_domains"] or combined["new_ipv4"] or combined["risk_changes"])
        if combined["new_repos"]: combined["summary"].append(f"{len(combined['new_repos'])} new repo(s)")
        if combined["deleted_repos"]: combined["summary"].append(f"{len(combined['deleted_repos'])} repo(s) removed/private/deleted")
        if repo_diffs: combined["summary"].append(f"{len(repo_diffs)} repo(s) changed")
        if combined["new_commits"]: combined["summary"].append(f"{len(combined['new_commits'])} new commit(s) across watched repos")
        if combined["new_files"]: combined["summary"].append(f"{len(combined['new_files'])} new file(s) across watched repos")
        if combined["deleted_files"]: combined["summary"].append(f"{len(combined['deleted_files'])} deleted file(s) across watched repos")
        if combined["modified_files"]: combined["summary"].append(f"{len(combined['modified_files'])} modified file(s) across watched repos")
        if combined["new_domains"]: combined["summary"].append(f"{len(combined['new_domains'])} new domain(s)")
        if combined["new_ipv4"]: combined["summary"].append(f"{len(combined['new_ipv4'])} new public IP(s)")
        if combined["risk_changes"]: combined["summary"].append(f"{len(combined['risk_changes'])} risk change(s)")
        if not combined["summary"]: combined["summary"].append("No changes detected since previous scan.")
        return combined

    def _watch_id(self, target_key: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.-]+", "_", target_key.lower()).strip("_")
        digest = hashlib.sha256(target_key.encode()).hexdigest()[:10]
        return f"{safe}_{digest}"[:140]

    async def _paginate(self, endpoint: str, params: dict[str, Any] | None = None, max_items: int = 100) -> list[dict[str, Any]]:
        params = dict(params or {})
        params["per_page"] = min(100, max_items)
        page, items = 1, []
        while len(items) < max_items:
            params["page"] = page
            batch = await self.gh.get(endpoint, params=params)
            if not isinstance(batch, list) or not batch:
                break
            items.extend(batch)
            if len(batch) < params["per_page"]:
                break
            page += 1
        return items[:max_items]

    def _account_scan_summary(self, profile: dict[str, Any], repos: list[dict[str, Any]], ok_results: list[dict[str, Any]], cross_repo: dict[str, Any]) -> dict[str, Any]:
        risk_scores = [r.get("summary", {}).get("risk_score") or 0 for r in ok_results]
        high = sum(1 for r in ok_results if r.get("summary", {}).get("risk_level") == "HIGH")
        med = sum(1 for r in ok_results if r.get("summary", {}).get("risk_level") == "MEDIUM")
        return {
            "login": profile.get("login"),
            "type": profile.get("type"),
            "created_at": profile.get("created_at"),
            "updated_at": profile.get("updated_at"),
            "html_url": profile.get("html_url"),
            "public_repos_seen": len(repos),
            "repos_scanned": len(ok_results),
            "high_risk_repos": high,
            "medium_risk_repos": med,
            "max_risk_score": max(risk_scores) if risk_scores else 0,
            "shared_domains": len((cross_repo.get("shared_domains") or {})),
            "shared_emails": len((cross_repo.get("shared_emails") or {})),
            "shared_contributors": len((cross_repo.get("shared_contributors") or {})),
        }

    def _send_watch_email(self, recipient: str, current: dict[str, Any], diff: dict[str, Any]) -> dict[str, Any]:
        status = {"attempted": True, "sent": False, "recipient": recipient}
        try:
            host = os.getenv("SMTP_HOST")
            port = int(os.getenv("SMTP_PORT", "587"))
            username = os.getenv("SMTP_USERNAME")
            password = os.getenv("SMTP_PASSWORD")
            sender = os.getenv("SMTP_FROM") or username
            if not host or not sender:
                status["error"] = "SMTP_HOST and SMTP_FROM/SMTP_USERNAME are required"
                return status
            subject = f"RepoTrace Watch Alert: {current.get('display_name') or current.get('target_key')}"
            body = [
                "RepoTrace detected watch-mode changes.",
                "",
                f"Target: {current.get('display_name') or current.get('target_key')}",
                f"Snapshot time: {current.get('created_at')}",
                "",
                "Summary:",
                *[f"- {x}" for x in diff.get("summary", [])],
                "",
                "New files:",
                *[f"- {x}" for x in diff.get("new_files", [])[:50]],
                "",
                "Deleted files:",
                *[f"- {x}" for x in diff.get("deleted_files", [])[:50]],
                "",
                "Modified files:",
                *[f"- {x}" for x in diff.get("modified_files", [])[:50]],
                "",
                "New domains:",
                *[f"- {x}" for x in diff.get("new_domains", [])[:50]],
                "",
                "New public IPs:",
                *[f"- {x}" for x in diff.get("new_ipv4", [])[:50]],
            ]
            if diff.get("repo_diffs"):
                body += ["", "Changed repos:"]
                for repo, rd in list(diff["repo_diffs"].items())[:30]:
                    body.append(f"- {repo}: {', '.join(rd.get('summary', []))}")
            msg = EmailMessage()
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = recipient
            msg.set_content("\n".join(body))
            with smtplib.SMTP(host, port, timeout=20) as smtp:
                smtp.starttls()
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(msg)
            status["sent"] = True
            return status
        except Exception as e:
            status["error"] = str(e)
            return status


    async def compare_commits(self, owner: str, repo: str, base: str, head: str) -> dict[str, Any]:
        cmp = await self.gh.get(f"/repos/{owner}/{repo}/compare/{base}...{head}")
        files, aggregate_added_text = [], ""
        for f in cmp.get("files", []):
            patch = f.get("patch") or ""
            added = "\n".join(line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))
            aggregate_added_text += "\n" + added
            files.append({"filename": f.get("filename"), "status": f.get("status"), "additions": f.get("additions"), "deletions": f.get("deletions"), "changes": f.get("changes"), "raw_url": f.get("raw_url"), "blob_url": f.get("blob_url"), "patch": patch[:12000], "added_iocs": extract_iocs(added), "suspicious_changes": self.detect_suspicious_diff(added, f.get("filename", ""))})
        aggregate_added_iocs = extract_iocs(aggregate_added_text)
        aggregate_suspicious_changes = self.detect_suspicious_diff(aggregate_added_text, "aggregate")
        flat_findings = []
        for f in files:
            for finding in f.get("suspicious_changes", []):
                flat_findings.append({"file": f.get("filename"), "type": finding.get("type"), "detail": finding.get("detail")})
        return {"status": cmp.get("status"), "base": base, "head": head, "ahead_by": cmp.get("ahead_by"), "behind_by": cmp.get("behind_by"), "total_commits": cmp.get("total_commits"), "html_url": cmp.get("html_url"), "permalink_url": cmp.get("permalink_url"), "files": files, "added_iocs": aggregate_added_iocs, "suspicious_findings": flat_findings, "aggregate_added_iocs": aggregate_added_iocs, "aggregate_suspicious_changes": aggregate_suspicious_changes}

    async def file_history(self, owner: str, repo: str, path: str, branch: str | None = None, max_commits: int = 50) -> dict[str, Any]:
        clean_path = path.strip().strip("/")
        if not clean_path:
            return {"owner": owner, "repo": repo, "path": path, "history": [], "commits": [], "error": "File path is required"}

        params = {"path": clean_path, "per_page": max_commits}
        if branch:
            params["sha"] = branch

        commits = await self.gh.get(f"/repos/{owner}/{repo}/commits", params=params)
        details = await self._bounded_gather(
            [lambda sha=c.get("sha"): self._commit_detail(owner, repo, sha) for c in commits[:max_commits]],
            8,
        )

        rows = []
        for d in details:
            if not d:
                continue
            matching_changes = []
            for f in d.get("files", []):
                filename = (f.get("filename") or "").strip("/")
                if filename == clean_path:
                    matching_changes.append(f)

            rows.append({
                "sha": d.get("sha"),
                "html_url": d.get("html_url"),
                "message": d.get("message"),
                "author_name": d.get("author_name"),
                "author_email": d.get("author_email"),
                "author_date": d.get("author_date"),
                "committer_name": d.get("committer_name"),
                "committer_email": d.get("committer_email"),
                "committer_date": d.get("committer_date"),
                "verified": d.get("verified"),
                "verification_reason": d.get("verification_reason"),
                "stats": d.get("stats"),
                "file_changes": matching_changes or d.get("files", [])[:3],
            })

        # Return both names so older/newer UI renderers work.
        return {"owner": owner, "repo": repo, "path": clean_path, "history": rows, "commits": rows}

    async def timeline(self, owner: str, repo: str, branch: str | None = None, max_commits: int = 80) -> dict[str, Any]:
        meta = await self.gh.get(f"/repos/{owner}/{repo}")
        branch = branch or meta.get("default_branch")
        commits = await self.gh.get(f"/repos/{owner}/{repo}/commits", params={"per_page": max_commits, "sha": branch})
        details = await self._bounded_gather([lambda sha=c.get("sha"): self._commit_detail(owner, repo, sha) for c in commits[:max_commits]], 8)
        events = [{"date": meta.get("created_at"), "type": "repo_created", "severity": "info", "message": "Repository created"}, {"date": meta.get("pushed_at"), "type": "latest_push", "severity": "info", "message": "Latest push timestamp"}]
        for c in details:
            if not c:
                continue
            sha = (c.get("sha") or "")[:7]
            msg = (c.get("message") or "").split("\n")[0]
            sev = "notice" if c.get("verified") is False else "info"
            events.append({"date": c.get("author_date"), "type": "commit", "severity": sev, "message": f"{sha}: {msg}", "author": c.get("author_name"), "verified": c.get("verified"), "sha": c.get("sha"), "html_url": c.get("html_url"), "url": c.get("html_url")})
            for f in c.get("files", []):
                fn = f.get("filename", "")
                patch = f.get("patch", "")
                if ".github/workflows/" in fn or fn.endswith((".env", ".npmrc")) or self.detect_suspicious_diff(patch, fn):
                    events.append({"date": c.get("author_date"), "type": "suspicious_change", "severity": "high", "message": f"{sha}: suspicious/sensitive change in {fn}", "detail": fn, "file": fn, "author": c.get("author_name"), "sha": c.get("sha"), "html_url": c.get("html_url"), "url": c.get("html_url")})
        events = sorted([e for e in events if e.get("date")], key=lambda x: x["date"])
        severity_counts = {}
        type_counts = {}
        for e in events:
            severity_counts[e.get("severity", "info")] = severity_counts.get(e.get("severity", "info"), 0) + 1
            type_counts[e.get("type", "event")] = type_counts.get(e.get("type", "event"), 0) + 1
        return {"owner": owner, "repo": repo, "branch": branch, "events": events, "summary": {"total_events": len(events), "severity_counts": severity_counts, "type_counts": type_counts}}

    async def compare_repos(self, repo_a_url: str, repo_b_url: str, max_files: int = 80, max_commits: int = 35) -> dict[str, Any]:
        a_target = parse_github_url(repo_a_url)
        b_target = parse_github_url(repo_b_url)
        a, b = await asyncio.gather(
            self.analyze(a_target, max_files=max_files, max_commits=max_commits),
            self.analyze(b_target, max_files=max_files, max_commits=max_commits),
        )
        def sset(obj, path, fallback=None):
            cur = obj
            for k in path:
                cur = cur.get(k, {}) if isinstance(cur, dict) else {}
            return set(cur if isinstance(cur, list) else (fallback or []))
        a_domains, b_domains = sset(a, ["infra_links", "domains"]), sset(b, ["infra_links", "domains"])
        a_emails, b_emails = sset(a, ["infra_links", "emails"]), sset(b, ["infra_links", "emails"])
        a_contrib, b_contrib = sset(a, ["infra_links", "contributors"]), sset(b, ["infra_links", "contributors"])
        a_files = {f.get("path") for f in a.get("files_analyzed", []) if f.get("path")}
        b_files = {f.get("path") for f in b.get("files_analyzed", []) if f.get("path")}
        shared = {
            "domains": sorted(a_domains & b_domains),
            "emails": sorted(a_emails & b_emails),
            "contributors": sorted(a_contrib & b_contrib),
            "file_paths": sorted(a_files & b_files)[:300],
        }
        risk_delta = (a.get("risk", {}).get("score") or 0) - (b.get("risk", {}).get("score") or 0)
        return {
            "repo_a": {"url": repo_a_url, "summary": self._bulk_summary(a), "result": a},
            "repo_b": {"url": repo_b_url, "summary": self._bulk_summary(b), "result": b},
            "shared": shared,
            "similarity": {
                "shared_domains": len(shared["domains"]),
                "shared_emails": len(shared["emails"]),
                "shared_contributors": len(shared["contributors"]),
                "shared_file_paths": len(shared["file_paths"]),
                "risk_score_delta_a_minus_b": risk_delta,
            },
        }

    async def analyst_report(self, owner: str, repo: str, branch: str | None = None, max_files: int = 100, max_commits: int = 60) -> str:
        target = GitHubTarget(kind="repo", owner=owner, repo=repo, branch=branch)
        r = await self.analyze(target, max_files=max_files, max_commits=max_commits)
        s, risk, perf = r["snapshot"], r["risk"], r["adaptive_scan"]
        lines = [f"# RepoTrace Analyst Report: {s.get('full_name')}", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", "", "## Snapshot", f"- URL: {s.get('html_url')}", f"- Created: {s.get('created_at')}", f"- Updated: {s.get('updated_at')}", f"- Last push: {s.get('pushed_at')}", f"- Default branch analyzed: {r.get('branch')}", f"- Stars/Forks: {s.get('stars')} / {s.get('forks')}", "", "## Adaptive Scan", f"- Mode: {perf.get('mode')}", f"- Strategy: {perf.get('strategy')}", f"- Files discovered/analyzed: {perf.get('total_files_discovered')} / {perf.get('files_analyzed')}", f"- Commits detailed: {perf.get('commits_selected_for_detail')}", "", "## Risk", f"- Level: {risk.get('level')}", f"- Score: {risk.get('score')}/100"]
        for reason in risk.get("reasons", []):
            lines.append(f"  - {reason}")
        lines += ["", "## Suspicious Findings"]
        for f in r.get("suspicious_findings", [])[:80]:
            lines.append(f"- {f.get('type')}: {f.get('detail')}")
        lines += ["", "## IOC Summary"]
        for k, vals in r.get("iocs", {}).items():
            lines.append(f"- {k}: {len(vals)}")
        lines += ["", "## Infrastructure Links"]
        infra = r.get("infra_links", {})
        for k in ("domains", "emails", "contributors", "external_services"):
            vals = infra.get(k, [])
            lines.append(f"- {k}: {', '.join(vals[:25]) if vals else 'None observed'}")
        lines += ["", "## Attack Narrative", self._attack_narrative(r), "", "## Analyst Recommendation", self._recommendation(r)]
        return "\n".join(lines)

    async def analyst_report_html(self, owner: str, repo: str, branch: str | None = None, max_files: int = 100, max_commits: int = 60) -> str:
        md = await self.analyst_report(owner, repo, branch=branch, max_files=max_files, max_commits=max_commits)
        body = self._markdown_to_html(md)
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>RepoTrace Report</title><style>body{{font-family:Segoe UI,Arial,sans-serif;background:#08111f;color:#e9f1ff;padding:32px;max-width:900px;margin:0 auto}}h1,h2{{color:#6ee7ff}}h1{{border-bottom:1px solid #1d2d44;padding-bottom:8px}}ul{{padding-left:22px}}li,p{{line-height:1.6}}li{{margin:4px 0}}code{{background:#11233b;padding:1px 5px;border-radius:4px}}</style></head><body>{body}</body></html>"""

    @staticmethod
    def _markdown_to_html(md: str) -> str:
        """Minimal but correct markdown renderer for the report subset we emit.

        Handles h1/h2/h3, bullet lists (grouped into <ul>), nested indented
        bullets, and paragraphs. Replaces the previous per-line heuristic that
        mangled any line containing a leading '-' mid-structure.
        """
        import html as _html

        def inline(text: str) -> str:
            esc = _html.escape(text)
            esc = re.sub(r"`([^`]+)`", r"<code>\1</code>", esc)
            esc = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", esc)
            return esc

        lines = md.splitlines()
        out: list[str] = []
        in_list = False

        def close_list():
            nonlocal in_list
            if in_list:
                out.append("</ul>")
                in_list = False

        for raw in lines:
            line = raw.rstrip()
            stripped = line.strip()
            if not stripped:
                close_list()
                continue
            heading = re.match(r"^(#{1,3})\s+(.*)$", stripped)
            bullet = re.match(r"^[-*]\s+(.*)$", stripped)
            if heading:
                close_list()
                level = len(heading.group(1))
                out.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
            elif bullet:
                if not in_list:
                    out.append("<ul>")
                    in_list = True
                out.append(f"<li>{inline(bullet.group(1))}</li>")
            else:
                close_list()
                out.append(f"<p>{inline(stripped)}</p>")
        close_list()
        return "\n".join(out)

    def detect_suspicious_diff(self, added_text: str, filename: str) -> list[dict[str, str]]:
        findings = []
        lower = filename.lower()
        if any(p in lower for p in (".env", ".npmrc", ".github/workflows/", "dockerfile", "requirements.txt", "package.json", "terraform.tfvars")):
            findings.append({"type": "sensitive_path_changed", "detail": filename})
        for name, rgx in DIFF_SUSPICIOUS_PATTERNS.items():
            if rgx.search(added_text or ""):
                findings.append({"type": "suspicious_added_content", "detail": name})
        return findings

    async def _safe_get(self, path: str, default: Any, params: dict | None = None) -> Any:
        try:
            return await self.gh.get(path, params=params)
        except Exception:
            return default

    async def _bounded_gather(self, call_factories: list, limit: int) -> list[Any]:
        sem = asyncio.Semaphore(max(1, limit))
        async def run(factory):
            async with sem:
                try:
                    return await factory()
                except Exception as e:
                    return {"error": str(e)}
        return await asyncio.gather(*(run(f) for f in call_factories)) if call_factories else []

    async def _analyze_file(self, owner: str, repo: str, branch: str, item: dict[str, Any], max_bytes: int) -> dict[str, Any]:
        path = item.get("path", "")
        raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        size = item.get("size") or 0
        result = {"path": path, "size": size, "git_blob_sha": item.get("sha"), "raw_download_url": raw_url, "html_url": f"https://github.com/{owner}/{repo}/blob/{branch}/{path}", "priority": self._file_priority(path, size)}
        if size > max_bytes:
            result["hash_note"] = f"Skipped hashing because file is over safety limit ({max_bytes} bytes). Increase MAX_FILE_HASH_BYTES if needed."
            return result
        data = await self.gh.get_bytes(raw_url, max_bytes=max_bytes)
        result["byte_count"] = len(data)
        result["hashes"] = hash_bytes(data)
        if self._should_text_scan(path, data):
            text = data.decode("utf-8", errors="ignore")
            result["iocs"] = extract_iocs(text)
            result["sample_text"] = text[:25000]
            result["content_type_guess"] = "text"
        else:
            result["iocs"] = empty_iocs()
            result["content_type_guess"] = "binary/non-text"
        return result

    def _should_text_scan(self, path: str, data: bytes) -> bool:
        if _ext(path) in TEXT_EXTS:
            return True
        if not data:
            return False
        sample = data[:4096]
        # Avoid running IOC regexes over obvious binaries, but still hash them and VT-check them.
        if b"\x00" in sample:
            return False
        try:
            sample.decode("utf-8")
            return True
        except Exception:
            return False

    def _select_files_for_inventory(self, files: list[dict], limit: int) -> list[dict]:
        # Full inventory mode: list every file up to the configured cap, not only risky files.
        # Priority is retained as metadata, but selection is path-stable for analyst completeness.
        return sorted(files, key=lambda f: f.get("path", ""))[:limit]

    async def _enrich_files_with_vt(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not files:
            return files
        if not self.vt.configured:
            for f in files:
                if f.get("hashes", {}).get("sha256"):
                    f["vt"] = {"configured": False, "status": "not_configured", "verdict": "VT key not configured"}
            return files
        lookup_limit = int(os.getenv("VT_LOOKUP_LIMIT", "300"))
        concurrency = max(1, min(int(os.getenv("VT_LOOKUP_CONCURRENCY", "3")), 6))
        candidates = [f for f in files if f.get("hashes", {}).get("sha256")][:lookup_limit]
        sem = asyncio.Semaphore(concurrency)
        async def one(f: dict[str, Any]):
            async with sem:
                f["vt"] = await self.vt.lookup_hash(f["hashes"]["sha256"])
                return f
        await asyncio.gather(*(one(f) for f in candidates))
        for f in files:
            if f.get("hashes", {}).get("sha256") and "vt" not in f:
                f["vt"] = {"configured": True, "status": "not_checked", "verdict": f"Not checked; VT_LOOKUP_LIMIT={lookup_limit} reached"}
        return files

    async def _commit_detail(self, owner: str, repo: str, sha: str | None) -> dict[str, Any]:
        if not sha:
            return {}
        c = await self.gh.get(f"/repos/{owner}/{repo}/commits/{sha}")
        return {"sha": c.get("sha"), "html_url": c.get("html_url"), "message": c.get("commit", {}).get("message"), "author_name": c.get("commit", {}).get("author", {}).get("name"), "author_email": c.get("commit", {}).get("author", {}).get("email"), "author_date": c.get("commit", {}).get("author", {}).get("date"), "committer_name": c.get("commit", {}).get("committer", {}).get("name"), "committer_email": c.get("commit", {}).get("committer", {}).get("email"), "committer_date": c.get("commit", {}).get("committer", {}).get("date"), "verified": c.get("commit", {}).get("verification", {}).get("verified"), "verification_reason": c.get("commit", {}).get("verification", {}).get("reason"), "stats": c.get("stats"), "files": [{"filename": f.get("filename"), "status": f.get("status"), "additions": f.get("additions"), "deletions": f.get("deletions"), "changes": f.get("changes"), "raw_url": f.get("raw_url"), "patch": (f.get("patch") or "")[:5000]} for f in c.get("files", [])[:80]]}

    def _adaptive_profile(self, repo_meta: dict, files: list[dict], truncated: bool, requested_files: int, requested_commits: int) -> dict[str, Any]:
        count = len(files); size_kb = repo_meta.get("size") or 0
        max_file_bytes = int(os.getenv("MAX_FILE_HASH_BYTES", "5000000"))
        if truncated or count > 8000 or size_kb > 750000:
            return {"mode": "huge", "strategy": "full inventory up to configured cap; GitHub may truncate enormous repos", "effective_max_files": min(requested_files, count, 1000), "effective_max_commits": min(requested_commits, 25), "file_concurrency": 6, "commit_concurrency": 4, "max_file_bytes": max_file_bytes, "rate_limit_tip": "Huge repo: increase max files carefully; VT/API limits may apply."}
        if count > 2500 or size_kb > 250000:
            return {"mode": "large", "strategy": "full file inventory up to configured cap", "effective_max_files": min(requested_files, count, 2500), "effective_max_commits": min(requested_commits, 40), "file_concurrency": 8, "commit_concurrency": 5, "max_file_bytes": max_file_bytes, "rate_limit_tip": "Large repo: full hashing can consume GitHub/VT quota; tune max files."}
        if count > 400 or size_kb > 50000:
            return {"mode": "medium", "strategy": "full file inventory + hashes + optional VT verdicts", "effective_max_files": min(requested_files, count, 4000), "effective_max_commits": min(requested_commits, 70), "file_concurrency": 12, "commit_concurrency": 8, "max_file_bytes": max_file_bytes, "rate_limit_tip": "Medium repo: full inventory mode enabled."}
        return {"mode": "small", "strategy": "complete file inventory + hashes + optional VT verdicts", "effective_max_files": min(requested_files, count, 5000), "effective_max_commits": min(requested_commits, 100), "file_concurrency": 16, "commit_concurrency": 10, "max_file_bytes": max_file_bytes, "rate_limit_tip": "Small repo: every returned file is hashed and listed."}

    def _file_priority(self, path: str, size: int) -> int:
        p = path.lower(); score = 0
        if any(x in p for x in PRIORITY_PATHS): score += 100
        if _ext(p) in INTERESTING_EXTS: score += 35
        if size < 200_000: score += 15
        if size > 1_500_000: score -= 60
        return score

    def _prioritize_files(self, files: list[dict], limit: int) -> list[dict]:
        return sorted(files, key=lambda f: (-self._file_priority(f.get("path", ""), f.get("size") or 0), f.get("size") or 0, f.get("path", "")))[:limit]

    def _repo_summary(self, r: dict[str, Any]) -> dict[str, Any]:
        license_value = (r.get("license") or {}).get("spdx_id") if isinstance(r.get("license"), dict) else r.get("license")
        return {
            "id": r.get("id"),
            "name": r.get("name"),
            "full_name": r.get("full_name"),
            "owner": r.get("owner", {}).get("login") if isinstance(r.get("owner"), dict) else None,
            "owner_created_at": r.get("owner_created_at"),
            "owner_type": r.get("owner_type"),
            "html_url": r.get("html_url") or r.get("web_url"),
            "description": r.get("description"),
            "created_at": r.get("created_at"),
            "updated_at": r.get("updated_at") or r.get("last_activity_at"),
            "pushed_at": r.get("pushed_at") or r.get("last_activity_at"),
            "default_branch": r.get("default_branch"),
            "size": r.get("size"),
            "storage_size_kb": r.get("storage_size_kb"),
            "commit_count": r.get("commit_count"),
            "stars": r.get("stargazers_count"),
            "forks": r.get("forks_count"),
            "watchers": r.get("watchers_count"),
            "open_issues": r.get("open_issues_count"),
            "license": license_value,
            "topics": r.get("topics", []),
            "fork": r.get("fork"),
            "archived": r.get("archived"),
            "disabled": r.get("disabled"),
            "visibility": r.get("visibility"),
            "namespace_full_path": r.get("namespace_full_path"),
            "namespace_kind": r.get("namespace_kind"),
            "readme_url": r.get("readme_url"),
            "issues_enabled": r.get("issues_enabled"),
            "merge_requests_enabled": r.get("merge_requests_enabled"),
            "wiki_enabled": r.get("wiki_enabled"),
            "jobs_enabled": r.get("jobs_enabled"),
            "snippets_enabled": r.get("snippets_enabled"),
            "container_registry_enabled": r.get("container_registry_enabled"),
            "packages_enabled": r.get("packages_enabled"),
            "shared_runners_enabled": r.get("shared_runners_enabled"),
            "lfs_enabled": r.get("lfs_enabled"),
            "request_access_enabled": r.get("request_access_enabled"),
            "empty_repo": r.get("empty_repo"),
            "import_status": r.get("import_status"),
            "creator_id": r.get("creator_id"),
            "languages": r.get("languages") or [],
        }

    def _release_summary(self, r: dict[str, Any]) -> dict[str, Any]:
        return {"name": r.get("name"), "tag_name": r.get("tag_name"), "created_at": r.get("created_at"), "published_at": r.get("published_at"), "html_url": r.get("html_url"), "assets": [{"name": a.get("name"), "size": a.get("size"), "download_count": a.get("download_count"), "browser_download_url": a.get("browser_download_url")} for a in r.get("assets", [])]}

    def _infra_links(self, repo: dict, files: list[dict], commits: list[dict], contributors: list[dict], iocs: dict) -> dict[str, Any]:
        emails = sorted(set([c.get("author_email") for c in commits if c.get("author_email")] + [c.get("committer_email") for c in commits if c.get("committer_email")]))
        contributors_logins = sorted(set(c.get("login") for c in contributors if isinstance(c, dict) and c.get("login")))
        domains = sorted(set(iocs.get("domains", [])))
        services = []
        service_map = {"amazonaws.com": "AWS", "cloudfront.net": "AWS CloudFront", "azurewebsites.net": "Azure", "windows.net": "Azure", "googleapis.com": "Google APIs", "firebaseio.com": "Firebase", "herokuapp.com": "Heroku", "vercel.app": "Vercel", "netlify.app": "Netlify", "githubusercontent.com": "GitHub raw/CDN", "ngrok": "ngrok/tunnel"}
        for d in domains:
            for needle, service in service_map.items():
                if needle in d:
                    services.append(service)
        return {"domains": domains[:200], "emails": emails[:100], "contributors": contributors_logins[:100], "external_services": sorted(set(services)), "domain_frequency": Counter(iocs.get("domains", [])).most_common(30)}

    def _suspicious_findings(self, files: list[dict], commits: list[dict], iocs: dict, infra: dict) -> list[dict[str, str]]:
        findings = []
        for f in files:
            path = f.get("path", "")
            if f.get("priority", 0) >= 100 or _ext(path) in {".ps1", ".sh", ".bat", ".cmd", ".hta", ".vbs"}:
                findings.append({"type": "interesting_file", "detail": path})
            if f.get("iocs", {}).get("secret_pattern_hits"):
                findings.append({"type": "secret_pattern", "detail": f"{path}: {', '.join(f['iocs']['secret_pattern_hits'])}"})
            vt = f.get("vt") or {}
            if vt.get("verdict") in {"malicious", "suspicious"}:
                findings.append({"type": "vt_" + vt.get("verdict"), "detail": f"{path}: VT {vt.get('malicious', 0)} malicious / {vt.get('suspicious', 0)} suspicious"})
        for c in commits:
            files_changed = c.get("files", [])
            if len(files_changed) > 40:
                findings.append({"type": "large_change", "detail": f"Commit {(c.get('sha') or '')[:7]} changed {len(files_changed)} files"})
            if c.get("verified") is False:
                findings.append({"type": "unverified_commit", "detail": f"{(c.get('sha') or '')[:7]} verification={c.get('verification_reason')}"})
            for cf in files_changed:
                fn, patch = cf.get("filename", ""), cf.get("patch", "")
                for d in self.detect_suspicious_diff(patch, fn):
                    findings.append({"type": d["type"], "detail": f"{(c.get('sha') or '')[:7]} {d['detail']}"})
        if iocs.get("secret_pattern_hits"):
            findings.append({"type": "aggregate_secret_patterns", "detail": ", ".join(iocs["secret_pattern_hits"])})
        if len(infra.get("external_services", [])) >= 5:
            findings.append({"type": "many_external_services", "detail": ", ".join(infra["external_services"][:20])})
        return findings[:160]

    def _risk_score(self, repo: dict, files: list[dict], commits: list[dict], iocs: dict, findings: list[dict], infra: dict) -> dict[str, Any]:
        # Delegates to the v2 confidence-tiered engine so a lone low-confidence
        # secret hit cannot dominate the score. Adds an `explanation` narrative
        # for backward compatibility with the dashboard.
        result = risk_engine.score_risk(repo, files, commits, iocs, findings, infra)
        result["explanation"] = risk_engine.attack_narrative({
            "risk": result,
            "suspicious_findings": findings,
            "iocs": iocs,
            "infra_links": infra,
            "files_analyzed": files,
        })
        return result

    def _attack_narrative(self, r: dict[str, Any]) -> str:
        return risk_engine.attack_narrative(r)


    def _bulk_summary(self, r: dict[str, Any]) -> dict[str, Any]:
        s = r.get("snapshot", {}) or {}
        risk = r.get("risk", {}) or {}
        adaptive = r.get("adaptive_scan", {}) or {}
        iocs = r.get("iocs", {}) or {}
        infra = r.get("infra_links", {}) or {}
        findings = r.get("suspicious_findings", []) or []
        commits = r.get("commits", []) or []
        contributors = infra.get("contributors", []) or []
        files = r.get("files_analyzed", []) or []
        topics = s.get("topics") or []
        return {
            "id": s.get("id"),
            "name": s.get("name") or r.get("user", {}).get("login"),
            "full_name": s.get("full_name") or r.get("user", {}).get("login"),
            "owner": s.get("owner"),
            "url": s.get("html_url") or r.get("user", {}).get("html_url"),
            "html_url": s.get("html_url") or r.get("user", {}).get("html_url"),
            "description": s.get("description"),
            "created_at": s.get("created_at"),
            "updated_at": s.get("updated_at"),
            "pushed_at": s.get("pushed_at"),
            "default_branch": s.get("default_branch"),
            "visibility": s.get("visibility"),
            "size": s.get("size"),
            "stars": s.get("stars"),
            "forks": s.get("forks"),
            "watchers": s.get("watchers"),
            "open_issues": s.get("open_issues"),
            "license": s.get("license"),
            "topics": topics,
            "topics_count": len(topics) if isinstance(topics, list) else 0,
            "fork": s.get("fork"),
            "archived": s.get("archived"),
            "disabled": s.get("disabled"),
            "risk": risk,
            "risk_level": risk.get("level"),
            "risk_score": risk.get("score"),
            "risk_reasons": risk.get("reasons", []),
            "scan_mode": adaptive.get("mode"),
            "scan_strategy": adaptive.get("strategy"),
            "files_analyzed": adaptive.get("files_analyzed"),
            "total_files": adaptive.get("total_files_discovered"),
            "directories": adaptive.get("total_dirs_discovered"),
            "commits_checked": adaptive.get("commits_selected_for_detail"),
            "runtime_ms": adaptive.get("elapsed_ms"),
            "findings": len(findings),
            "domains": len(iocs.get("domains", [])),
            "urls": len(iocs.get("urls", [])),
            "emails": len(iocs.get("emails", [])),
            "ipv4": len(iocs.get("ipv4", [])),
            "secret_hits": len(iocs.get("secret_pattern_hits", [])),
            "external_services": len(infra.get("external_services", [])),
            "contributors": len(contributors),
            "recent_commits": len(commits),
            "priority_files": sum(1 for f in files if (f.get("priority") or 0) >= 100),
            "files_hashed": sum(1 for f in files if f.get("hashes")),
            "vt_malicious_files": sum(1 for f in files if (f.get("vt") or {}).get("verdict") == "malicious"),
            "vt_suspicious_files": sum(1 for f in files if (f.get("vt") or {}).get("verdict") == "suspicious"),
        }

    def _infra_graph_from_cross_repo(self, cross_repo: dict[str, Any]) -> list[dict[str, str]]:
        graph = []
        type_map = {
            "shared_domains": "domain",
            "shared_emails": "email",
            "shared_contributors": "contributor",
        }
        for key, kind in type_map.items():
            values = cross_repo.get(key, {}) if isinstance(cross_repo, dict) else {}
            if not isinstance(values, dict):
                continue
            for indicator, repos in values.items():
                if isinstance(repos, dict):
                    repo_list = list(repos.keys())
                elif isinstance(repos, list):
                    repo_list = repos
                else:
                    repo_list = []
                for repo in sorted(set(str(r) for r in repo_list if r)):
                    graph.append({"repo": repo, "ioc": str(indicator), "type": kind})
        return graph[:250]

    def _cross_repo_links(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        domains, emails, contributors = defaultdict(list), defaultdict(list), defaultdict(list)
        for r in results:
            name = r.get("snapshot", {}).get("full_name", "unknown")
            for d in r.get("infra_links", {}).get("domains", []): domains[d].append(name)
            for e in r.get("infra_links", {}).get("emails", []): emails[e].append(name)
            for c in r.get("infra_links", {}).get("contributors", []): contributors[c].append(name)
        return {"shared_domains": {k:v for k,v in domains.items() if len(set(v)) > 1}, "shared_emails": {k:v for k,v in emails.items() if len(set(v)) > 1}, "shared_contributors": {k:v for k,v in contributors.items() if len(set(v)) > 1}}

    def _recommendation(self, r: dict[str, Any]) -> str:
        level = r.get("risk", {}).get("level")
        if level == "HIGH":
            return "High risk: manually review suspicious commits, validate any secret-pattern hits, and inspect workflow/deployment changes before trusting this repository."
        if level == "MEDIUM":
            return "Medium risk: review sensitive files, recent unverified commits, and extracted external infrastructure before operational use."
        return "Low risk based on scanned subset: preserve the report as evidence and run deeper targeted analysis if the repo is operationally important."
