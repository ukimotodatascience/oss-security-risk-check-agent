from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G6UnsafePluginExecutionRule:
    """危険なプラグイン実行がないか"""

    rule_id = "G-6"
    category = "runtime"
    title = "Unsafe Plugin Execution"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
