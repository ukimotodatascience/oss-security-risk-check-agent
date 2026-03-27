from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class K3CopyleftRiskRule:
    """Copyleftライセンスのリスクがないか"""

    rule_id = "K-3"
    category = "license"
    title = "Copyleft Risk"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
