from pathlib import Path
import subprocess
from typing import List

from src.models import RiskRecord, Severity


class J4LowBusFactorRule:
    """バスファクターが低いか"""

    rule_id = "J-4"
    category = "maintenance"
    title = "Low Bus Factor"
    severity = Severity.MEDIUM

    _LOW_CONTRIBUTOR_THRESHOLD = 2

    def _count_distinct_authors(self, target: Path) -> int:
        try:
            proc = subprocess.run(
                ["git", "-C", str(target), "shortlog", "-sne", "--all"],
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

        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        return len(lines)

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        contributor_count = self._count_distinct_authors(target)
        if contributor_count <= 0:
            return records

        if contributor_count <= self._LOW_CONTRIBUTOR_THRESHOLD:
            severity = Severity.HIGH if contributor_count == 1 else Severity.MEDIUM
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=severity,
                    file_path=".git",
                    line=1,
                    message=f"コミット作者数が {contributor_count} 名で、継続性（バスファクター）リスクの可能性があります",
                )
            )

        return records
