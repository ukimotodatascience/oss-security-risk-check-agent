from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G4HostMountRiskRule:
    """ホストマウントの危険性がないか"""

    rule_id = "G-4"
    category = "runtime"
    title = "Host Mount Risk"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
