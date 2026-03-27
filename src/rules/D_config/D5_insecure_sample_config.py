from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class D5InsecureSampleConfigRule:
    """サンプルコードの危険な設定がないか"""

    rule_id = "D-5"
    category = "config"
    title = "Insecure Sample Config"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
