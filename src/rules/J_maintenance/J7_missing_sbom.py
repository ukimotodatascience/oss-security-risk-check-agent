from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class J7MissingSbomRule:
    """SBOMが不足していないか"""

    rule_id = "J-7"
    category = "maintenance"
    title = "Missing SBOM"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
