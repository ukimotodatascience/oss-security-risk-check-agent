from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


_GITHUB_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


@dataclass(frozen=True)
class GitHubRepoRef:
    owner: str
    repo: str


def parse_github_repo_url(raw_url: str) -> GitHubRepoRef:
    """GitHub の HTTPS repository URL を owner/repo に正規化する。"""

    parsed = urlparse(raw_url.strip())
    if parsed.scheme != "https":
        raise ValueError("TARGET_REPO_URL は https:// の GitHub URL のみ許可します。")
    if parsed.hostname != "github.com":
        raise ValueError("TARGET_REPO_URL は github.com の URL のみ対応しています。")
    if parsed.username or parsed.password or parsed.port:
        raise ValueError("TARGET_REPO_URL に認証情報やポート番号は含められません。")

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        raise ValueError(
            "GitHub URL は https://github.com/{owner}/{repo} 形式で指定してください。"
        )

    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    if not _GITHUB_NAME_RE.fullmatch(owner) or not _GITHUB_NAME_RE.fullmatch(repo):
        raise ValueError("GitHub の owner/repo 形式が不正です。")

    return GitHubRepoRef(owner=owner, repo=repo)
