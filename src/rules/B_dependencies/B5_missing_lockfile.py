from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class B5MissingLockfileRule:
    """lockfile不在で再現性が弱くないか"""

    rule_id = "B-5"
    category = "dependencies"
    title = "Missing Lockfile"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
