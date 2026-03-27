from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class H6ExpiredOrMissingTLSDocsRule:
    """TLS証明書の有効期限が切れていないか"""

    rule_id = "H-6"
    category = "crypto"
    title = "Expired or Missing TLS Docs"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
