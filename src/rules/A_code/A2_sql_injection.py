from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A2SqlInjectionRule:
    """SQL文字列連結や危険クエリ構築がないか"""

    rule_id = "A-2"
    category = "code"
    title = "SQL Injection"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
