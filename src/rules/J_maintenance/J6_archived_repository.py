from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class J6ArchivedRepositoryRule:
    """アーカイブされたリポジトリがないか"""

    rule_id = "J-6"
    category = "maintenance"
    title = "Archived Repository"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
