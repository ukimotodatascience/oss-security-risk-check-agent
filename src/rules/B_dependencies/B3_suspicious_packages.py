from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class B3SuspiciousPackagesRule:
    """typosquattingや不審な依存がないか"""

    rule_id = "B-3"
    category = "dependencies"
    title = "Suspicious Packages"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
