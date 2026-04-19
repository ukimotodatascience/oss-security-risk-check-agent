from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import (
    collect_dependency_declarations,
    collect_js_imports,
    collect_python_imports,
)


class B6UnusedDependenciesRule:
    """不要依存が多く攻撃面を広げていないか"""

    rule_id = "B-6"
    category = "dependencies"
    title = "Unused Dependencies"
    severity = Severity.MEDIUM

    _KNOWN_PY_IMPORT_MAP = {
        "pyyaml": "yaml",
        "pillow": "PIL",
        "python-dotenv": "dotenv",
        "beautifulsoup4": "bs4",
        "scikit-learn": "sklearn",
    }

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        py_imports = {x.lower() for x in collect_python_imports(target)}
        js_imports = {x.lower() for x in collect_js_imports(target)}

        for dep in collect_dependency_declarations(target):
            if dep.ecosystem == "python":
                expected = self._KNOWN_PY_IMPORT_MAP.get(dep.name, dep.name).split(
                    ".", 1
                )[0]
                used = expected.lower() in py_imports
            else:
                used = dep.name.lower() in js_imports

            if used:
                continue

            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.LOW,
                    file_path=dep.file_path,
                    line=dep.line,
                    message=f"{dep.name} は依存定義にありますが、コード参照が確認できません（未使用の可能性）。",
                )
            )

        return records
