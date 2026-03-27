from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class K5NoncommercialRestrictionRule:
    """商用利用の制限がないか"""

    rule_id = "K-5"
    category = "license"
    title = "Noncommercial Restriction"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
