from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class B2UnpinnedVersionsRule:
    """バージョン固定が不十分でないか"""

    rule_id = "B-2"
    category = "dependencies"
    title = "Unpinned Versions"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
