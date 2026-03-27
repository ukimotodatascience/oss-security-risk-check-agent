from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G3BroadLinuxCapabilitiesRule:
    """広範囲のLinux Capabilitiesがないか"""

    rule_id = "G-3"
    category = "runtime"
    title = "Broad Linux Capabilities"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
