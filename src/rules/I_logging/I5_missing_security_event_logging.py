from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class I5MissingSecurityEventLoggingRule:
    """セキュリティイベントロギングが不足していないか"""

    rule_id = "I-5"
    category = "logging"
    title = "Missing Security Event Logging"
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
    _SECURITY_EVENT_PATTERN = re.compile(
        r"(?i)\b(?:login\s*failed|auth(?:entication)?\s*failed|invalid\s*password|invalid\s*token|access\s*denied|forbidden|rate\s*limit(?:ed)?|too\s*many\s*requests|brute\s*force|account\s*lock(?:ed)?|mfa\s*failed|csrf|suspicious\s*activity)\b"
    )
    _EVENT_LOG_HINT = re.compile(
        r"(?i)\b(?:security_event|audit|logger\.|log\.|logging\.|siem|event_log|emit\(|track\()"
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
                if not self._SECURITY_EVENT_PATTERN.search(stripped):
                    continue

                window_start = max(0, idx - 4)
                window_end = min(len(lines), idx + 3)
                context = "\n".join(lines[window_start:window_end])
                if self._EVENT_LOG_HINT.search(context):
                    continue

                sev = (
                    Severity.HIGH
                    if re.search(
                        r"(?i)\b(?:brute\s*force|account\s*lock(?:ed)?|rate\s*limit(?:ed)?|csrf)\b",
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
                        message="ログイン失敗・レート制限超過などのセキュリティイベントが記録されていない可能性があります",
                    )
                )

        return records
