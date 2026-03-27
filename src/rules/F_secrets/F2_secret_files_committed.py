from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class F2SecretFilesCommittedRule:
    """秘密情報がコミットされていないか"""

    rule_id = "F-2"
    category = "secrets"
    title = "Secret Files Committed"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
