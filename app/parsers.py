from dataclasses import dataclass
from urllib.parse import urlparse, unquote


@dataclass
class GitHubTarget:
    kind: str  # user | repo | tree | blob
    owner: str
    repo: str | None = None
    branch: str | None = None
    path: str | None = None
    platform: str = "github"
    project_path: str | None = None
    web_url: str | None = None


def parse_github_url(url: str) -> GitHubTarget:
    u = urlparse(url.strip())
    host = u.netloc.lower()
    if host in {"github.com", "www.github.com"}:
        return _parse_github(u)
    if host in {"gitlab.com", "www.gitlab.com"} or host.endswith(".gitlab.com"):
        return _parse_gitlab(u)
    raise ValueError("Only GitHub/GitLab URLs are supported")


def _parse_github(u) -> GitHubTarget:
    parts = [unquote(p) for p in u.path.strip("/").split("/") if p]
    if not parts:
        raise ValueError("Provide a GitHub user, repo, folder, or file URL")
    if len(parts) == 1:
        return GitHubTarget(kind="user", owner=parts[0], platform="github", web_url=u.geturl())
    owner, repo = parts[0], parts[1]
    if len(parts) == 2:
        return GitHubTarget(kind="repo", owner=owner, repo=repo, platform="github", project_path=f"{owner}/{repo}", web_url=u.geturl())
    marker = parts[2]
    if marker in {"tree", "blob"} and len(parts) >= 4:
        branch = parts[3]
        path = "/".join(parts[4:]) if len(parts) > 4 else ""
        return GitHubTarget(kind=marker, owner=owner, repo=repo, branch=branch, path=path, platform="github", project_path=f"{owner}/{repo}", web_url=u.geturl())
    return GitHubTarget(kind="repo", owner=owner, repo=repo, platform="github", project_path=f"{owner}/{repo}", web_url=u.geturl())


def _parse_gitlab(u) -> GitHubTarget:
    parts = [unquote(p) for p in u.path.strip("/").split("/") if p]
    if not parts:
        raise ValueError("Provide a GitLab group/user, project, folder, or file URL")
    # GitLab file/tree URLs look like: /namespace/project/-/blob/branch/path
    if "-" in parts:
        dash = parts.index("-")
        project_parts = parts[:dash]
        marker = parts[dash + 1] if len(parts) > dash + 1 else None
        if marker in {"tree", "blob"} and len(parts) > dash + 2:
            branch = parts[dash + 2]
            path = "/".join(parts[dash + 3:]) if len(parts) > dash + 3 else ""
            owner = project_parts[0]
            repo = project_parts[-1]
            project_path = "/".join(project_parts)
            return GitHubTarget(kind=marker, owner=owner, repo=repo, branch=branch, path=path, platform="gitlab", project_path=project_path, web_url=u.geturl())
        project_path = "/".join(project_parts)
        return GitHubTarget(kind="repo", owner=project_parts[0], repo=project_parts[-1], platform="gitlab", project_path=project_path, web_url=u.geturl())
    # Ambiguous GitLab namespace. Treat single part as user/group, 2+ parts as project path.
    if len(parts) == 1:
        return GitHubTarget(kind="user", owner=parts[0], platform="gitlab", project_path=parts[0], web_url=u.geturl())
    project_path = "/".join(parts)
    return GitHubTarget(kind="repo", owner=parts[0], repo=parts[-1], platform="gitlab", project_path=project_path, web_url=u.geturl())
