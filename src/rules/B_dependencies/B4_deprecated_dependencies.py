from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import (
    collect_dependency_declarations,
    parse_version_tuple,
)


class B4DeprecatedDependenciesRule:
    """非推奨・EOL依存が使われていないか"""

    rule_id = "B-4"
    category = "dependencies"
    title = "Deprecated Dependencies"
    severity = Severity.MEDIUM

    _DEPRECATED_THRESHOLDS = {
        # package: eol_below_version
        "django": (3, 2),
        "flask": (2, 0),
        "urllib3": (2, 0),
        "setuptools": (45, 0),
        "react": (17, 0, 0),
    }

    _FULLY_DEPRECATED = {
        "easy_install": "非推奨の配布インストーラです",
        "left-pad": "歴史的に供給安定性リスクの事例がある依存です",
    }

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for dep in collect_dependency_declarations(target):
            if dep.name in self._FULLY_DEPRECATED:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=dep.file_path,
                        line=dep.line,
                        message=f"{dep.name}: {self._FULLY_DEPRECATED[dep.name]}",
                    )
                )
                continue

            threshold = self._DEPRECATED_THRESHOLDS.get(dep.name)
            if not threshold:
                continue
            version = parse_version_tuple(dep.spec)
            if version is None:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.LOW,
                        file_path=dep.file_path,
                        line=dep.line,
                        message=f"{dep.name} は旧版のEOL懸念がありますが、specから判定できません（'{dep.spec or '(none)'}'）。",
                    )
                )
                continue

            if version < threshold:
                label = ".".join([str(x) for x in threshold])
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=dep.file_path,
                        line=dep.line,
                        message=f"{dep.name} {dep.spec} は非推奨/EOL系列の可能性があります（目安: < {label}）。",
                    )
                )

        return records
