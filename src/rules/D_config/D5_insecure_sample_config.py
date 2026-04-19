from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class D5InsecureSampleConfigRule:
    """サンプルコードの危険な設定がないか"""

    rule_id = "D-5"
    category = "config"
    title = "Insecure Sample Config"
    severity = Severity.MEDIUM

    _SAMPLE_NAME_HINT = re.compile(
        r"(?i)(?:example|sample|template|\.env\.example|\.env\.sample)"
    )
    _TEXT_EXTS = {
        ".env",
        ".ini",
        ".cfg",
        ".conf",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".properties",
        ".txt",
    }
    _INSECURE_SAMPLE_PATTERNS = (
        re.compile(
            r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?(?:password|admin|root|123456|qwerty)[\"']?"
        ),
        re.compile(
            r"(?i)\b(?:secret(?:_key)?|api[_-]?key|token|jwt[_-]?secret)\b\s*[:=]\s*[\"']?(?:secret|changeme|change_me|default|test|dummy)[\"']?"
        ),
        re.compile(
            r"(?i)\b(?:debug|disable[_-]?(?:auth|security)|allow[_-]?insecure)\b\s*[:=]\s*(?:1|true|yes|on)\b"
        ),
    )

    def _is_sample_file(self, p: Path) -> bool:
        lowered = str(p).lower()
        return bool(self._SAMPLE_NAME_HINT.search(lowered))

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if p.suffix.lower() in self._TEXT_EXTS and self._is_sample_file(p):
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
                if not stripped or stripped.startswith("#"):
                    continue

                if any(pat.search(stripped) for pat in self._INSECURE_SAMPLE_PATTERNS):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="サンプル設定に弱い認証情報/危険な値が残っている可能性があります",
                        )
                    )

        return records
