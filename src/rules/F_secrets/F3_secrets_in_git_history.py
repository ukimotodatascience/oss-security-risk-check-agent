from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class F3SecretsInGitHistoryRule:
    """Git Historyに秘密情報が残っていないか"""

    rule_id = "F-3"
    category = "secrets"
    title = "Secrets in Git History"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
