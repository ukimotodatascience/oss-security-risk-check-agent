from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C3ThirdPartyActionUsageRule:
    """外部Actionの使用が多く攻撃面を広げていないか"""

    rule_id = "C-3"
    category = "cicd"
    title = "Third Party Action Usage"
    severity = Severity.MEDIUM

    _USES_LINE = re.compile(r"^\s*uses\s*:\s*([^\s#]+)")

    def _is_third_party(self, uses_target: str) -> bool:
        target = uses_target.strip("\"'")
        if target.startswith("./") or target.startswith("docker://"):
            return False
        owner = target.split("@", 1)[0].split("/", 1)[0].lower()
        return owner not in {"actions", "github"}

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

            third_party_count = 0
            first_line = None
            for idx, line in enumerate(lines, start=1):
                m = self._USES_LINE.match(line)
                if not m:
                    continue
                if self._is_third_party(m.group(1)):
                    third_party_count += 1
                    if first_line is None:
                        first_line = idx

            if third_party_count >= 6:
                sev = Severity.HIGH
            elif third_party_count >= 3:
                sev = Severity.MEDIUM
            else:
                continue

            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=sev,
                    file_path=str(wf.relative_to(target)),
                    line=first_line,
                    message=f"外部公開 Action の利用数が多めです（{third_party_count} 件）",
                )
            )

        return records
