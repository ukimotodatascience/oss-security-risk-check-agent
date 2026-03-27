from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class H3WeakCryptoAlgorithmsRule:
    """脆弱な暗号アルゴリズムがないか"""

    rule_id = "H-3"
    category = "crypto"
    title = "Weak Crypto Algorithms"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
