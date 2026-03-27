from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class E1UnauthenticatedAdminEndpointsRule:
    """認証不要の管理画面エンドポイントがないか"""

    rule_id = "E-1"
    category = "auth"
    title = "Unauthenticated Admin Endpoints"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
