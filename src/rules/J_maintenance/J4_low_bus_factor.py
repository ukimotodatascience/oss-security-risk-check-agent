from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class J4LowBusFactorRule:
    """バスファクターが低いか"""

    rule_id = "J-4"
    category = "maintenance"
    title = "Low Bus Factor"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
