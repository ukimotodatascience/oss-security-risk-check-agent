from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C2UnpinnedActionsRule:
    """ActionsがSHA固定されているか"""

    rule_id = "C-2"
    category = "cicd"
    title = "Unpinned Actions"
    severity = Severity.MEDIUM

    _SHA_PIN = re.compile(r"^[0-9a-fA-F]{40}$")
    _USES_LINE = re.compile(r"^\s*uses\s*:\s*([^\s#]+)")

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        workflows = target / ".github" / "workflows"
        if not workflows.exists():
            return records

        for wf in workflows.rglob("*.y*ml"):
            try:
                lines = wf.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(wf.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                m = self._USES_LINE.match(line)
                if not m:
                    continue

                uses_target = m.group(1).strip("\"'")
                if uses_target.startswith("./") or uses_target.startswith("docker://"):
                    continue
                if "@" not in uses_target:
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=idx,
                            message="GitHub Action がバージョン指定なしで参照されています",
                        )
                    )
                    continue

                ref = uses_target.rsplit("@", 1)[1]
                if not self._SHA_PIN.fullmatch(ref):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="GitHub Action がコミット SHA 固定ではありません",
                        )
                    )

        return records
