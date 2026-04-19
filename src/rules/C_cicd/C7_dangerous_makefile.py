from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C7DangerousMakefileRule:
    """危険なMakefileがないか"""

    rule_id = "C-7"
    category = "cicd"
    title = "Dangerous Makefile"
    severity = Severity.MEDIUM

    _NETWORK_EXEC = re.compile(
        r"\b(?:curl|wget)\b[^\n\r]*\|\s*(?:sh|bash|zsh|ksh)\b",
        re.IGNORECASE,
    )
    _DANGEROUS_CMDS = (
        re.compile(r"\bsudo\b", re.IGNORECASE),
        re.compile(r"\brm\s+-rf\s+/(?:\s|$)", re.IGNORECASE),
        re.compile(r"\bchmod\s+777\b", re.IGNORECASE),
        re.compile(r"\bdocker\s+run\b[^\n\r]*--privileged\b", re.IGNORECASE),
    )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        makefiles = [
            p
            for p in target.rglob("*")
            if p.is_file() and p.name.lower().startswith("makefile")
        ]

        for mk in makefiles:
            try:
                lines = mk.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(mk.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if self._NETWORK_EXEC.search(stripped):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=idx,
                            message="Makefile で外部取得スクリプトを直接実行しています",
                        )
                    )
                    continue

                for pat in self._DANGEROUS_CMDS:
                    if pat.search(stripped):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.MEDIUM,
                                file_path=rel_path,
                                line=idx,
                                message="Makefile に破壊的/高権限コマンドの可能性があります",
                            )
                        )
                        break

        return records
