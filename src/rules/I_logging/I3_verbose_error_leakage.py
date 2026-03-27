from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class I3VerboseErrorLeakageRule:
    """詳細なエラー情報が漏れていないか"""

    rule_id = "I-3"
    category = "logging"
    title = "Verbose Error Leakage"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
