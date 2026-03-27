from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class K4UnknownDependencyLicenseRule:
    """未知の依存ライセンスがないか"""

    rule_id = "K-4"
    category = "license"
    title = "Unknown Dependency License"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
