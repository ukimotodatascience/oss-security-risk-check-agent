from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class E2MissingAuthorizationChecksRule:
    """認証不要のエンドポイントがないか"""

    rule_id = "E-2"
    category = "auth"
    title = "Missing Authorization Checks"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
