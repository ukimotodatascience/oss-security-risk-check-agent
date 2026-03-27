from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class D3OpenBindAddressRule:
    """危険なバインドアドレスがないか"""

    rule_id = "D-3"
    category = "config"
    title = "Open Bind Address"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
