from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class I4UnsafeRequestLoggingRule:
    """危険なリクエストロギングがないか"""

    rule_id = "I-4"
    category = "logging"
    title = "Unsafe Request Logging"
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
    _LOG_CALL_PATTERN = re.compile(
        r"(?i)\b(?:logger\.(?:debug|info|warning|warn|error|critical)|log\.(?:debug|info|warning|warn|error|critical)|console\.(?:log|debug|info|warn|error)|print\s*\()"
    )
    _UNSAFE_REQUEST_PATTERN = re.compile(
        r"(?i)(?:authorization|req\.headers|request\.headers|http_headers|bearer\s+|set-cookie|cookie|request\.body|req\.body|raw_body|payload\s*=\s*request|json\s*\.\s*dumps\(request\.|dump\(request\.)"
    )
    _MASK_HINT_PATTERN = re.compile(
        r"(?i)(?:redact|mask|sanitize|anonymiz|\*{3,}|\[REDACTED\]|\[MASKED\])"
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
                if not self._LOG_CALL_PATTERN.search(stripped):
                    continue
                if not self._UNSAFE_REQUEST_PATTERN.search(stripped):
                    continue
                if self._MASK_HINT_PATTERN.search(stripped):
                    continue

                sev = (
                    Severity.HIGH
                    if re.search(
                        r"(?i)\bauthorization|bearer|set-cookie|cookie\b", stripped
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
                        message="Authorization ヘッダやリクエストボディをマスクせずログ出力している可能性があります",
                    )
                )

        return records
