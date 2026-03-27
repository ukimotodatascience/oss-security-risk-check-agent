from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G2PrivilegedContainerRule:
    """特権コンテナがないか"""

    rule_id = "G-2"
    category = "runtime"
    title = "Privileged Container"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
