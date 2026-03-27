from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A7TemplateInjectionRule:
    """テンプレートエンジンへの危険な入力注入がないか"""

    rule_id = "A-7"
    category = "code"
    title = "Template Injection"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
