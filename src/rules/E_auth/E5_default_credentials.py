from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class E5DefaultCredentialsRule:
    """デフォルトの認証情報がないか"""

    rule_id = "E-5"
    category = "auth"
    title = "Default Credentials"
    severity = Severity.MEDIUM

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
        ".py",
        ".js",
        ".ts",
        ".txt",
    }
    _USERNAME_PATTERN = re.compile(
        r"(?i)\b(?:username|user|login|admin_user)\b\s*[:=]\s*[\"']?(?:admin|root|administrator|test|guest)[\"']?"
    )
    _PASSWORD_PATTERN = re.compile(
        r"(?i)\b(?:password|passwd|pwd|admin_pass|default_pass)\b\s*[:=]\s*[\"']?(?:password|admin|root|123456|qwerty|guest|changeme|default)[\"']?"
    )
    _COMBINED_INLINE_PATTERN = re.compile(
        r"(?i)(?:admin\s*[:/|]\s*admin|root\s*[:/|]\s*root|admin\s*[:/|]\s*password)"
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
                if not stripped or stripped.startswith("#"):
                    continue

                username_hit = bool(self._USERNAME_PATTERN.search(stripped))
                password_hit = bool(self._PASSWORD_PATTERN.search(stripped))
                combined_hit = bool(self._COMBINED_INLINE_PATTERN.search(stripped))
                if not (username_hit or password_hit or combined_hit):
                    continue

                severity = (
                    Severity.HIGH
                    if (combined_hit or (username_hit and password_hit))
                    else Severity.MEDIUM
                )
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=severity,
                        file_path=rel_path,
                        line=idx,
                        message="既知のデフォルト認証情報（admin/password 等）が含まれている可能性があります",
                    )
                )

        return records
