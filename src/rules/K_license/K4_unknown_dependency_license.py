from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import collect_dependency_declarations
from src.rules.K_license._license_utils import (
    build_dependency_license_map,
    collect_dependency_licenses,
)


class K4UnknownDependencyLicenseRule:
    """未知の依存ライセンスがないか"""

    rule_id = "K-4"
    category = "license"
    title = "Unknown Dependency License"
    severity = Severity.MEDIUM

    _UNKNOWN_HINTS = {
        "",
        "unknown",
        "unlicensed",
        "none",
        "see license in",
        "n/a",
    }

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        dep_licenses = collect_dependency_licenses(target)
        dep_decls = collect_dependency_declarations(target)
        if not dep_decls:
            return records

        license_map = build_dependency_license_map(dep_licenses)

        for dep in dep_decls:
            lic = license_map.get(dep.name, "").strip()
            if not lic or lic.lower() in self._UNKNOWN_HINTS:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=dep.file_path,
                        line=dep.line,
                        message=f"依存 '{dep.name}' のライセンス情報が不明です",
                    )
                )

        return records
