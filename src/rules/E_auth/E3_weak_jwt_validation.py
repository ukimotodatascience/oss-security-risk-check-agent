from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class E3WeakJWTValidationRule:
    """脆弱なJWT検証がないか"""

    rule_id = "E-3"
    category = "auth"
    title = "Weak JWT Validation"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
