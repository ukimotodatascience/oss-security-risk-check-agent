from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class D2DebugEnabledRule:
    """デバッグ用ログ出力がないか"""

    rule_id = "D-2"
    category = "config"
    title = "Debug Enabled"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
