from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class D7InsecureFilePermissionsRule:
    """危険なファイルパーミッションがないか"""

    rule_id = "D-7"
    category = "config"
    title = "Insecure File Permissions"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
