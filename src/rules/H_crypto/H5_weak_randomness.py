from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class H5WeakRandomnessRule:
    """脆弱なランダム性がないか"""

    rule_id = "H-5"
    category = "crypto"
    title = "Weak Randomness"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
