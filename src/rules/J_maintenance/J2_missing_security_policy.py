from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class J2MissingSecurityPolicyRule:
    """セキュリティポリシーが不足していないか"""

    rule_id = "J-2"
    category = "maintenance"
    title = "Missing Security Policy"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
