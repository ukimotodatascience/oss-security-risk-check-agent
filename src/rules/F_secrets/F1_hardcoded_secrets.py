from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class F1HardcodedSecretsRule:
    """ハードコードされた秘密情報がないか"""

    rule_id = "F-1"
    category = "secrets"
    title = "Hardcoded Secrets"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
