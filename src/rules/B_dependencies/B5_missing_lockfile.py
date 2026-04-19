from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import discover_lockfiles, has_file


class B5MissingLockfileRule:
    """lockfile不在で再現性が弱くないか"""

    rule_id = "B-5"
    category = "dependencies"
    title = "Missing Lockfile"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        lockfiles = discover_lockfiles(target)

        has_python_manifest = has_file(target, "requirements.txt") or has_file(
            target, "pyproject.toml"
        )
        has_node_manifest = has_file(target, "package.json")

        if has_python_manifest and not (
            {"poetry.lock", "Pipfile.lock", "uv.lock"} & lockfiles
        ):
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=None,
                    line=None,
                    message="Python依存が宣言されていますが lockfile が見つかりません（poetry.lock / Pipfile.lock / uv.lock）。",
                )
            )

        if has_node_manifest and not (
            {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"} & lockfiles
        ):
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=None,
                    line=None,
                    message="Node依存が宣言されていますが lockfile が見つかりません（package-lock.json / yarn.lock / pnpm-lock.yaml）。",
                )
            )

        return records
