from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class J5NoRecentReleaseRule:
    """最近のリリースがないか"""

    rule_id = "J-5"
    category = "maintenance"
    title = "No Recent Release"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
