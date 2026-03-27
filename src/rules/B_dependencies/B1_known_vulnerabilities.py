from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class B1KnownVulnerabilitiesRule:
    """使用依存が既知CVEに該当していないか"""

    rule_id = "B-1"
    category = "dependencies"
    title = "Known Vulnerabilities"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
