from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class H4CustomCryptoRule:
    """独自暗号化がないか"""

    rule_id = "H-4"
    category = "crypto"
    title = "Custom Crypto"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
