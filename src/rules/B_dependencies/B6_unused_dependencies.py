from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class B6UnusedDependenciesRule:
    """不要依存が多く攻撃面を広げていないか"""

    rule_id = "B-6"
    category = "dependencies"
    title = "Unused Dependencies"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
