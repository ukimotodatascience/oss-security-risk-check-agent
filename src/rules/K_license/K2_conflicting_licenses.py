from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.K_license._license_utils import (
    collect_dependency_licenses,
    extract_spdx_like_tokens,
)


class K2ConflictingLicensesRule:
    """競合するライセンスがないか"""

    rule_id = "K-2"
    category = "license"
    title = "Conflicting Licenses"
    severity = Severity.MEDIUM

    # 代表的な非互換ペア（厳密な法務判断の代替ではなく、注意喚起用の簡易判定）
    _INCOMPATIBLE_SPDX_PAIRS = (
        ("GPL-2.0", "APACHE-2.0"),
        ("GPL-2.0-ONLY", "APACHE-2.0"),
    )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        dep_licenses = collect_dependency_licenses(target)
        if not dep_licenses:
            return records

        seen_tokens = set()
        for dep in dep_licenses:
            seen_tokens.update(extract_spdx_like_tokens(dep.license_expr))

        for left, right in self._INCOMPATIBLE_SPDX_PAIRS:
            if left in seen_tokens and right in seen_tokens:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=None,
                        line=None,
                        message=(
                            f"依存ライセンスに '{left}' と '{right}' が混在しています。"
                            "配布条件が衝突する可能性があるため、互換性を確認してください"
                        ),
                    )
                )

        return records
