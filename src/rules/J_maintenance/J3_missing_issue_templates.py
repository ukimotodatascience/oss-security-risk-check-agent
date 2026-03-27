from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class J3MissingIssueTemplatesRule:
    """Issue Templateが不足していないか"""

    rule_id = "J-3"
    category = "maintenance"
    title = "Missing Issue Templates"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
