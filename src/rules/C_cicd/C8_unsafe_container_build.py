from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C8UnsafeContainerBuildRule:
    """危険なコンテナビルドがないか"""

    rule_id = "C-8"
    category = "cicd"
    title = "Unsafe Container Build"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
