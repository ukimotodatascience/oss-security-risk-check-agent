from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class E4InsecureSessionConfigRule:
    """危険なセッション設定がないか"""

    rule_id = "E-4"
    category = "auth"
    title = "Insecure Session Config"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
