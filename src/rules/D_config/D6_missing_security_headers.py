from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class D6MissingSecurityHeadersRule:
    """セキュリティヘッダーの不足がないか"""

    rule_id = "D-6"
    category = "config"
    title = "Missing Security Headers"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
