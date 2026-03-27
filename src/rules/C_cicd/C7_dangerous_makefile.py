from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C7DangerousMakefileRule:
    """危険なMakefileがないか"""

    rule_id = "C-7"
    category = "cicd"
    title = "Dangerous Makefile"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
