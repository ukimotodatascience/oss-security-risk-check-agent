from pathlib import Path
import subprocess
from datetime import datetime, timezone
from typing import List

from src.models import RiskRecord, Severity


class J1StaleProjectRule:
    """古いプロジェクトがないか"""

    rule_id = "J-1"
    category = "maintenance"
    title = "Stale Project"
    severity = Severity.MEDIUM

    _STALE_DAYS_THRESHOLD = 180
    _VERY_STALE_DAYS_THRESHOLD = 365

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        try:
            proc = subprocess.run(
                ["git", "-C", str(target), "log", "-1", "--format=%ct"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False,
            )
        except OSError:
            return records

        if proc.returncode != 0:
            return records

        ts = proc.stdout.strip()
        if not ts.isdigit():
            return records

        last_commit_at = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        stale_days = (datetime.now(timezone.utc) - last_commit_at).days

        if stale_days < self._STALE_DAYS_THRESHOLD:
            return records

        sev = (
            Severity.HIGH
            if stale_days >= self._VERY_STALE_DAYS_THRESHOLD
            else Severity.MEDIUM
        )
        records.append(
            RiskRecord(
                rule_id=self.rule_id,
                category=self.category,
                title=self.title,
                severity=sev,
                file_path=".git",
                line=1,
                message=f"最終コミットから {stale_days} 日経過しており、メンテナンス停滞の可能性があります",
            )
        )

        return records
