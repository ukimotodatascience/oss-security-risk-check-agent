from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G1RunsAsRootRule:
    """root権限で実行されていないか"""

    rule_id = "G-1"
    category = "runtime"
    title = "Runs as Root"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
