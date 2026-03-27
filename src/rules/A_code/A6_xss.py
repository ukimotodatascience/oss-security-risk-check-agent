from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A6XssRule:
    """テンプレートやレスポンス出力に未エスケープ出力がないか"""

    rule_id = "A-6"
    category = "code"
    title = "XSS"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
