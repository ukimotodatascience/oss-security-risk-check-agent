from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class K1MissingLicenseRule:
    """ライセンスが不足していないか"""

    rule_id = "K-1"
    category = "license"
    title = "Missing License"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
