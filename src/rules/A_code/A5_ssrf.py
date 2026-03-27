from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A5SsrfRule:
    """外部入力でURLアクセス先を制御可能になっていないか"""

    rule_id = "A-5"
    category = "code"
    title = "SSRF"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
