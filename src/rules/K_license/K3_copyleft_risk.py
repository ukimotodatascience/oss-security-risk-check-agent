from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.K_license._license_utils import (
    collect_dependency_licenses,
    extract_spdx_like_tokens,
)


class K3CopyleftRiskRule:
    """Copyleftライセンスのリスクがないか"""

    rule_id = "K-3"
    category = "license"
    title = "Copyleft Risk"
    severity = Severity.MEDIUM

    _STRONG_COPYLEFT = {
        "GPL-2.0",
        "GPL-2.0-ONLY",
        "GPL-2.0-OR-LATER",
        "GPL-3.0",
        "GPL-3.0-ONLY",
        "GPL-3.0-OR-LATER",
        "AGPL-3.0",
        "AGPL-3.0-ONLY",
        "AGPL-3.0-OR-LATER",
    }

    _CLOSED_SOURCE_HINT_FILES = (
        "EULA",
        "EULA.txt",
        "NOTICE",
        "NOTICE.txt",
    )

    _CLOSED_SOURCE_HINT_TERMS = (
        "all rights reserved",
        "proprietary",
        "closed source",
        "commercial license",
    )

    def _looks_closed_distribution(self, target: Path) -> bool:
        for name in self._CLOSED_SOURCE_HINT_FILES:
            p = target / name
            if p.is_file():
                return True

        for name in ("README.md", "README.txt", "README.rst"):
            p = target / name
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            if any(term in text for term in self._CLOSED_SOURCE_HINT_TERMS):
                return True

        return False

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        dep_licenses = collect_dependency_licenses(target)
        if not dep_licenses:
            return records

        has_strong_copyleft = False
        copyleft_examples: List[str] = []
        for dep in dep_licenses:
            tokens = extract_spdx_like_tokens(dep.license_expr)
            matched = sorted(tokens & self._STRONG_COPYLEFT)
            if matched:
                has_strong_copyleft = True
                copyleft_examples.append(f"{dep.package}: {', '.join(matched)}")

        if not has_strong_copyleft:
            return records

        sev = (
            Severity.HIGH
            if self._looks_closed_distribution(target)
            else Severity.MEDIUM
        )
        sample = "; ".join(copyleft_examples[:3])
        records.append(
            RiskRecord(
                rule_id=self.rule_id,
                category=self.category,
                title=self.title,
                severity=sev,
                file_path=None,
                line=None,
                message=(
                    "強いコピーレフト（GPL/AGPL）依存が検出されました。"
                    f"配布形態との整合を確認してください（例: {sample}）"
                ),
            )
        )

        return records
