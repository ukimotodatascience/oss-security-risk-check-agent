from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A8UnsafeEvalRule:
    """eval, execなどの危険評価処理がないか"""

    rule_id = "A-8"
    category = "code"
    title = "Unsafe Eval"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
