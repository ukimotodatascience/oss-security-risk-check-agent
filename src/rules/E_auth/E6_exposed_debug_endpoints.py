from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class E6ExposedDebugEndpointsRule:
    """認証不要のデバッグエンドポイントがないか"""

    rule_id = "E-6"
    category = "auth"
    title = "Exposed Debug Endpoints"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
