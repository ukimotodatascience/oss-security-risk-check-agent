from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C2UnpinnedActionsRule:
    """ActionsがSHA固定されているか"""

    rule_id = "C-2"
    category = "cicd"
    title = "Unpinned Actions"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
