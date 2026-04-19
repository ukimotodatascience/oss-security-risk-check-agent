from pathlib import Path
import json
import os
import re
import subprocess
from typing import List

from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

from src.models import RiskRecord, Severity


class J6ArchivedRepositoryRule:
    """アーカイブされたリポジトリがないか"""

    rule_id = "J-6"
    category = "maintenance"
    title = "Archived Repository"
    severity = Severity.MEDIUM

    _GITHUB_REMOTE = re.compile(
        r"github\.com[:/](?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?$",
        re.IGNORECASE,
    )

    def _extract_github_repo(self, target: Path) -> tuple[str, str] | None:
        try:
            proc = subprocess.run(
                ["git", "-C", str(target), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False,
            )
        except OSError:
            return None

        if proc.returncode != 0:
            return None

        remote = proc.stdout.strip()
        m = self._GITHUB_REMOTE.search(remote)
        if not m:
            return None
        return m.group("owner"), m.group("repo")

    def _is_archived_on_github(self, owner: str, repo: str) -> bool | None:
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        req = Request(
            api_url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "oss-security-risk-check-agent",
            },
        )

        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            req.add_header("Authorization", f"Bearer {token}")

        try:
            with urlopen(req, timeout=5) as resp:
                payload = resp.read().decode("utf-8", errors="ignore")
        except (URLError, HTTPError, TimeoutError, OSError):
            return None

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None

        archived = data.get("archived")
        return bool(archived) if isinstance(archived, bool) else None

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        repo = self._extract_github_repo(target)
        if not repo:
            return records

        archived = self._is_archived_on_github(*repo)
        if archived is True:
            owner, name = repo
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=None,
                    line=None,
                    message=f"GitHub リポジトリ {owner}/{name} は archived=true です",
                )
            )

        return records
