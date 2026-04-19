from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.K_license._license_utils import (
    collect_dependency_licenses,
    find_license_files,
)


class K5NoncommercialRestrictionRule:
    """商用利用の制限がないか"""

    rule_id = "K-5"
    category = "license"
    title = "Noncommercial Restriction"
    severity = Severity.MEDIUM

    _NC_HINTS = (
        "noncommercial",
        "non-commercial",
        "for non commercial use",
        "not for commercial use",
        "for personal use only",
        "cc-by-nc",
        "cc by-nc",
    )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        dep_licenses = collect_dependency_licenses(target)
        for dep in dep_licenses:
            lic = dep.license_expr.lower()
            if any(h in lic for h in self._NC_HINTS):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=dep.file_path,
                        line=dep.line,
                        message=f"依存 '{dep.package}' に非商用制限を含む可能性のあるライセンス（{dep.license_expr}）が指定されています",
                    )
                )

        for lf in find_license_files(target):
            try:
                text = lf.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            if any(h in text for h in self._NC_HINTS):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=str(lf.relative_to(target)),
                        line=1,
                        message="プロジェクトライセンス本文に非商用利用制限（NC）を示す記述が見つかりました",
                    )
                )

        return records
