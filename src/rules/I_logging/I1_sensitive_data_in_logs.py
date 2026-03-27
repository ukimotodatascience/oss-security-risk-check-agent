from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class I1SensitiveDataInLogsRule:
    """ログに機密データが漏れていないか"""

    rule_id = "I-1"
    category = "logging"
    title = "Sensitive Data in Logs"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
