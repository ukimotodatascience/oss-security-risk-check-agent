from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class H1PlaintextTransportRule:
    """平文トランスポートがないか"""

    rule_id = "H-1"
    category = "crypto"
    title = "Plaintext Transport"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
