from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class A3UnsafeDeserializationRule:
    """危険なデシリアライズがないか"""

    rule_id = "A-3"
    category = "code"
    title = "Unsafe Deserialization"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
