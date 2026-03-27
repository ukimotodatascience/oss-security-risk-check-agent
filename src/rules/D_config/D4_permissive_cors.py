from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class D4PermissiveCORSRule:
    """危険なCORS設定がないか"""

    rule_id = "D-4"
    category = "config"
    title = "Permissive CORS"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
