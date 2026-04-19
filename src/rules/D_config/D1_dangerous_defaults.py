from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class D1DangerousDefaultsRule:
    """危険なデフォルト設定がないか"""

    rule_id = "D-1"
    category = "config"
    title = "Dangerous Defaults"
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
        ".py",
        ".js",
        ".ts",
        ".properties",
    }
    _DANGEROUS_DEFAULT_PATTERNS = (
        re.compile(
            r"(?i)\b(?:secret(?:_key)?|api[_-]?key|token|auth[_-]?token|jwt[_-]?secret)\b\s*[:=]\s*[\"']?(?:changeme|change_me|default|secret|test|dummy)[\"']?"
        ),
        re.compile(
            r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?(?:password|admin|root|123456|qwerty|changeme|default)[\"']?"
        ),
        re.compile(
            r"(?i)\b(?:disable[_-]?(?:auth|security)|skip[_-]?(?:auth|security)|allow[_-]?insecure|insecure[_-]?mode)\b\s*[:=]\s*(?:1|true|yes|on)\b"
        ),
        re.compile(
            r"(?i)\b(?:ssl|tls|cert)(?:[_-]?(?:verify|verification))\b\s*[:=]\s*(?:0|false|no|off)\b"
        ),
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if p.name.lower() in {"dockerfile", "compose.yml", "compose.yaml"}:
                yield p
                continue
            if p.suffix.lower() in self._TEXT_EXTS:
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

                if any(
                    pat.search(stripped) for pat in self._DANGEROUS_DEFAULT_PATTERNS
                ):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="危険なデフォルト設定（弱い秘密情報/保護無効化）が残っている可能性があります",
                        )
                    )

        return records
