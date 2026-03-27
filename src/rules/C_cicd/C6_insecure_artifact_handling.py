from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C6InsecureArtifactHandlingRule:
    """成果物の検証不在になっていないか"""

    rule_id = "C-6"
    category = "cicd"
    title = "Insecure Artifact Handling"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
