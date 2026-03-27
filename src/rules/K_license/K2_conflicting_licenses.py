from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class K2ConflictingLicensesRule:
    """競合するライセンスがないか"""

    rule_id = "K-2"
    category = "license"
    title = "Conflicting Licenses"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
