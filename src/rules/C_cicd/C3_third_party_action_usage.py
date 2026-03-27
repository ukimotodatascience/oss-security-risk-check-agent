from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C3ThirdPartyActionUsageRule:
    """外部Actionの使用が多く攻撃面を広げていないか"""

    rule_id = "C-3"
    category = "cicd"
    title = "Third Party Action Usage"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
