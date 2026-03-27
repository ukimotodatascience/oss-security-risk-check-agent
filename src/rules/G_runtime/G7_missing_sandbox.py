from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G7MissingSandboxRule:
    """サンドボックスがないか"""

    rule_id = "G-7"
    category = "runtime"
    title = "Missing Sandbox"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
