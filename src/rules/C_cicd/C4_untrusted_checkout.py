from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C4UntrustedCheckoutRule:
    """外部PRや外部コードを取り組む構成になっていないか"""

    rule_id = "C-4"
    category = "cicd"
    title = "Untrusted Checkout"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
