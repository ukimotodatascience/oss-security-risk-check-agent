from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import collect_dependency_declarations


class B3SuspiciousPackagesRule:
    """typosquattingや不審な依存がないか"""

    rule_id = "B-3"
    category = "dependencies"
    title = "Suspicious Packages"
    severity = Severity.MEDIUM

    _COMMON_PACKAGES = {
        "requests",
        "numpy",
        "pandas",
        "flask",
        "django",
        "pyyaml",
        "urllib3",
        "react",
        "express",
        "lodash",
        "axios",
        "typescript",
    }

    def _is_edit_distance_one(self, a: str, b: str) -> bool:
        if a == b:
            return False
        la, lb = len(a), len(b)
        if abs(la - lb) > 1:
            return False

        i = j = diff = 0
        while i < la and j < lb:
            if a[i] == b[j]:
                i += 1
                j += 1
                continue
            diff += 1
            if diff > 1:
                return False
            if la > lb:
                i += 1
            elif lb > la:
                j += 1
            else:
                i += 1
                j += 1
        if i < la or j < lb:
            diff += 1
        return diff == 1

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for dep in collect_dependency_declarations(target):
            suspicious_reason = None
            name = dep.name
            spec = dep.spec.lower()

            if any(token in name for token in ("..", "__", "tmp", "test", "malware")):
                suspicious_reason = "パッケージ名に不審なトークンが含まれています"
            elif any(
                spec.startswith(prefix)
                for prefix in ("git+http://", "http://", "https://", "file:")
            ):
                suspicious_reason = (
                    "レジストリ外の取得元が指定されており、供給元確認が必要です"
                )
            else:
                for legit in self._COMMON_PACKAGES:
                    if self._is_edit_distance_one(name, legit):
                        suspicious_reason = f"'{legit}' に酷似した名前で、タイポスクワッティングの可能性があります"
                        break

            if suspicious_reason:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=dep.file_path,
                        line=dep.line,
                        message=f"{name}: {suspicious_reason}",
                    )
                )

        return records
