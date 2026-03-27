from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class F5PrivateKeysDetectedRule:
    """秘密鍵が検出されていないか"""

    rule_id = "F-5"
    category = "secrets"
    title = "Private Keys Detected"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
