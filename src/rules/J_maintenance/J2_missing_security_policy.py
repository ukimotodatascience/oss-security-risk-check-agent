from pathlib import Path
import re
from typing import List

from src.models import RiskRecord, Severity


class J2MissingSecurityPolicyRule:
    """セキュリティポリシーが不足していないか"""

    rule_id = "J-2"
    category = "maintenance"
    title = "Missing Security Policy"
    severity = Severity.MEDIUM

    _SECURITY_FILES = (
        "SECURITY.md",
        "SECURITY.txt",
        "SECURITY.rst",
        ".github/SECURITY.md",
        "docs/SECURITY.md",
    )
    _README_FILES = ("README.md", "README.rst", "README.txt")
    _SECURITY_CONTACT_HINT = re.compile(
        r"(?is)(security|vulnerability|脆弱性).{0,120}(report|contact|連絡|報告|disclosure)"
    )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for rel in self._SECURITY_FILES:
            if (target / rel).is_file():
                return records

        for readme_name in self._README_FILES:
            readme = target / readme_name
            if not readme.is_file():
                continue
            try:
                content = readme.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if self._SECURITY_CONTACT_HINT.search(content):
                return records

        records.append(
            RiskRecord(
                rule_id=self.rule_id,
                category=self.category,
                title=self.title,
                severity=Severity.MEDIUM,
                file_path=None,
                line=None,
                message="SECURITY.md や脆弱性報告窓口の記載が見つかりませんでした",
            )
        )
        return records
