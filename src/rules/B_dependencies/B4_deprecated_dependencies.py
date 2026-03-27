from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class B4DeprecatedDependenciesRule:
    """非推奨・EOL依存が使われていないか"""

    rule_id = "B-4"
    category = "dependencies"
    title = "Deprecated Dependencies"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
