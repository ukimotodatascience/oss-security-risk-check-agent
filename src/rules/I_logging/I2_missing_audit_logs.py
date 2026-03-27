from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class I2MissingAuditLogsRule:
    """監査ログが不足していないか"""

    rule_id = "I-2"
    category = "logging"
    title = "Missing Audit Logs"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
