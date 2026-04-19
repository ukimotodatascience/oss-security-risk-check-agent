from pathlib import Path
import subprocess
from datetime import datetime, timezone
from typing import List

from src.models import RiskRecord, Severity


class J5NoRecentReleaseRule:
    """最近のリリースがないか"""

    rule_id = "J-5"
    category = "maintenance"
    title = "No Recent Release"
    severity = Severity.MEDIUM

    _NO_RELEASE_DAYS_THRESHOLD = 180
    _VERY_OLD_RELEASE_DAYS_THRESHOLD = 365
    _CHANGELOG_NAMES = ("CHANGELOG.md", "CHANGELOG.rst", "CHANGELOG.txt", "HISTORY.md")

    def _last_release_timestamp(self, target: Path) -> int:
        try:
            proc = subprocess.run(
                [
                    "git",
                    "-C",
                    str(target),
                    "for-each-ref",
                    "--sort=-creatordate",
                    "--format=%(creatordate:unix)",
                    "refs/tags",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False,
            )
        except OSError:
            return 0

        if proc.returncode != 0:
            return 0

        for line in proc.stdout.splitlines():
            s = line.strip()
            if s.isdigit():
                return int(s)
        return 0

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        latest_release_ts = self._last_release_timestamp(target)
        if latest_release_ts > 0:
            released_at = datetime.fromtimestamp(latest_release_ts, tz=timezone.utc)
            days_since_release = (datetime.now(timezone.utc) - released_at).days
            if days_since_release >= self._NO_RELEASE_DAYS_THRESHOLD:
                severity = (
                    Severity.HIGH
                    if days_since_release >= self._VERY_OLD_RELEASE_DAYS_THRESHOLD
                    else Severity.MEDIUM
                )
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=severity,
                        file_path=".git/tags",
                        line=1,
                        message=f"最新リリース（タグ）から {days_since_release} 日経過しています",
                    )
                )
            return records

        # タグが無い場合は CHANGELOG の有無で補足
        has_changelog = any((target / name).is_file() for name in self._CHANGELOG_NAMES)
        if not has_changelog:
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=None,
                    line=None,
                    message="リリースタグおよび CHANGELOG が見つからず、リリース状況を確認できませんでした",
                )
            )

        return records
