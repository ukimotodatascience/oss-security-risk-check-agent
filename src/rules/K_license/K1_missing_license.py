from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.K_license._license_utils import (
    collect_project_license_expressions,
    find_license_files,
)


class K1MissingLicenseRule:
    """ライセンスが不足していないか"""

    rule_id = "K-1"
    category = "license"
    title = "Missing License"
    severity = Severity.MEDIUM

    _AMBIGUOUS_LICENSE_MARKERS = (
        "unknown",
        "unlicensed",
        "see license in",
        "no license",
        "none",
    )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        license_files = find_license_files(target)
        manifest_licenses = collect_project_license_expressions(target)

        if not license_files and not manifest_licenses:
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=None,
                    line=None,
                    message="LICENSE ファイルまたは manifest 上のライセンス表記（SPDX）が見つかりませんでした",
                )
            )
            return records

        for file_path, lic in manifest_licenses:
            lower = lic.strip().lower()
            if any(marker in lower for marker in self._AMBIGUOUS_LICENSE_MARKERS):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.LOW,
                        file_path=file_path,
                        line=None,
                        message=f"ライセンス表記が不明瞭です（'{lic}'）。明確な SPDX 識別子の記載を推奨します",
                    )
                )

        return records
