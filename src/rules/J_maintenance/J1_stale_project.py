from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class J1StaleProjectRule:
    """古いプロジェクトがないか"""

    rule_id = "J-1"
    category = "maintenance"
    title = "Stale Project"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
