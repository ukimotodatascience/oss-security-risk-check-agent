from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity


class J3MissingIssueTemplatesRule:
    """Issue Templateが不足していないか"""

    rule_id = "J-3"
    category = "maintenance"
    title = "Missing Issue Templates"
    severity = Severity.MEDIUM

    _TEMPLATE_DIRS = (
        ".github/ISSUE_TEMPLATE",
        "docs/ISSUE_TEMPLATE",
    )
    _TEMPLATE_FILES = (
        ".github/ISSUE_TEMPLATE.md",
        ".gitlab/issue_templates/bug.md",
    )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for rel in self._TEMPLATE_FILES:
            if (target / rel).is_file():
                return records

        for rel_dir in self._TEMPLATE_DIRS:
            d = target / rel_dir
            if not d.is_dir():
                continue
            has_template = any(p.is_file() for p in d.rglob("*.md")) or any(
                p.is_file() for p in d.rglob("*.yml")
            )
            if has_template:
                return records

        records.append(
            RiskRecord(
                rule_id=self.rule_id,
                category=self.category,
                title=self.title,
                severity=Severity.MEDIUM,
                file_path=None,
                line=None,
                message="Issue テンプレート（.github/ISSUE_TEMPLATE など）が見つかりませんでした",
            )
        )
        return records
