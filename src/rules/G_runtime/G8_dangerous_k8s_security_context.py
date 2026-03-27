from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class G8DangerousK8SSecurityContextRule:
    """危険なK8S Security Contextがないか"""

    rule_id = "G-8"
    category = "runtime"
    title = "Dangerous K8S Security Context"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
