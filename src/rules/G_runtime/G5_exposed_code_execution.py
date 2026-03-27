from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G5ExposedCodeExecutionRule:
    """コード実行が外部から制御可能になっていないか"""

    rule_id = "G-5"
    category = "runtime"
    title = "Exposed Code Execution"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
