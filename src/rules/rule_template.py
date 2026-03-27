from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class RuleTemplate:
    rule_id = "X-1"
    category = "example"
    title = "Example rule"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
