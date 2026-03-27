from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class I5MissingSecurityEventLoggingRule:
    """セキュリティイベントロギングが不足していないか"""

    rule_id = "I-5"
    category = "logging"
    title = "Missing Security Event Logging"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
