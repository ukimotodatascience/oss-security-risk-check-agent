from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class I4UnsafeRequestLoggingRule:
    """危険なリクエストロギングがないか"""

    rule_id = "I-4"
    category = "logging"
    title = "Unsafe Request Logging"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
