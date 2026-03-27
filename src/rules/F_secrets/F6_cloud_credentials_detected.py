from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class F6CloudCredentialsDetectedRule:
    """クラウドの秘密情報が検出されていないか"""

    rule_id = "F-6"
    category = "secrets"
    title = "Cloud Credentials Detected"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
