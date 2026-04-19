from pathlib import Path
import re
import subprocess
from typing import List
from src.models import RiskRecord, Severity


class F3SecretsInGitHistoryRule:
    """Git Historyに秘密情報が残っていないか"""

    rule_id = "F-3"
    category = "secrets"
    title = "Secrets in Git History"
    severity = Severity.MEDIUM

    _SECRET_PATTERNS = (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    )

    _MAX_OUTPUT_CHARS = 1_000_000

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        try:
            proc = subprocess.run(
                ["git", "-C", str(target), "log", "-p", "--all", "--no-color"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                check=False,
            )
        except OSError:
            return records

        if proc.returncode != 0 or not proc.stdout:
            return records

        output = proc.stdout
        if len(output) > self._MAX_OUTPUT_CHARS:
            output = output[: self._MAX_OUTPUT_CHARS]

        for pat in self._SECRET_PATTERNS:
            if pat.search(output):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=".git/history",
                        line=1,
                        message="Git 履歴中に秘密情報形式の文字列が検出されました",
                    )
                )
                break

        return records
