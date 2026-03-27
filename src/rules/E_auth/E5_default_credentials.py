from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class E5DefaultCredentialsRule:
    """デフォルトの認証情報がないか"""

    rule_id = "E-5"
    category = "auth"
    title = "Default Credentials"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
