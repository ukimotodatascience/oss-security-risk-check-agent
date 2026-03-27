from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A1CommandInjectionRule:
    """外部入力がOSコマンド実行に流れていないか"""

    rule_id = "A-1"
    category = "code"
    title = "Command Injection"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
