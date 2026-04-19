from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import (
    collect_dependency_declarations,
    is_loose_spec,
)


class B2UnpinnedVersionsRule:
    """バージョン固定が不十分でないか"""

    rule_id = "B-2"
    category = "dependencies"
    title = "Unpinned Versions"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for dep in collect_dependency_declarations(target):
            if not is_loose_spec(dep):
                continue
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=dep.file_path,
                    line=dep.line,
                    message=f"{dep.name} のバージョン指定が固定されていません（spec: '{dep.spec or '(none)'}'）。",
                )
            )

        return records
