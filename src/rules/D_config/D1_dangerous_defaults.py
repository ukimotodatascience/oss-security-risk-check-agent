from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class D1DangerousDefaultsRule:
    """危険なデフォルト設定がないか"""

    rule_id = "D-1"
    category = "config"
    title = "Dangerous Defaults"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
