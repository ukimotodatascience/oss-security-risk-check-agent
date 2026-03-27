from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A4PathTraversalRule:
    """ユーザー入力を用いた危険なファイル参照がないか"""

    rule_id = "A-4"
    category = "code"
    title = "Path Traversal"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
