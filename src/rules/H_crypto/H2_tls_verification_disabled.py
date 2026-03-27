from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class H2TLSVerificationDisabledRule:
    """TLS検証が無効になっていないか"""

    rule_id = "H-2"
    category = "crypto"
    title = "TLS Verification Disabled"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
