from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class I2MissingAuditLogsRule:
    """監査ログが不足していないか"""

    rule_id = "I-2"
    category = "logging"
    title = "Missing Audit Logs"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
    }
    _AUDIT_RELEVANT_ACTION = re.compile(
        r"(?i)\b(?:login|logout|authenticate|authorize|permission|role|grant|revoke|reset[_-]?password|change[_-]?password|delete[_-]?(?:user|account)|create[_-]?user|api[_-]?key|token\s*rotate)\b"
    )
    _AUDIT_LOG_HINT = re.compile(
        r"(?i)\b(?:audit|logger\.|log\.|logging\.|console\.|print\(|security_event|event_log|siem)"
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._TEXT_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for file_path in self._iter_candidate_files(target):
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                if not self._AUDIT_RELEVANT_ACTION.search(stripped):
                    continue

                window_start = max(0, idx - 4)
                window_end = min(len(lines), idx + 3)
                context = "\n".join(lines[window_start:window_end])
                if self._AUDIT_LOG_HINT.search(context):
                    continue

                sev = (
                    Severity.HIGH
                    if re.search(
                        r"(?i)\b(?:grant|revoke|permission|role|delete[_-]?(?:user|account))\b",
                        stripped,
                    )
                    else Severity.MEDIUM
                )
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=sev,
                        file_path=rel_path,
                        line=idx,
                        message="認証・認可変更などの重要操作に対する監査ログが不足している可能性があります",
                    )
                )

        return records
