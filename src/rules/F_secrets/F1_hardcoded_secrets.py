from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class F1HardcodedSecretsRule:
    """ハードコードされた秘密情報がないか"""

    rule_id = "F-1"
    category = "secrets"
    title = "Hardcoded Secrets"
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
        ".swift",
        ".kt",
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
        ".md",
    }
    _KEY_VALUE_SECRET_PATTERN = re.compile(
        r"(?i)\b(?:api[_-]?key|token|secret(?:_key)?|passwd|password|pwd|auth[_-]?token)\b\s*[:=]\s*[\"']([^\"'\n]{6,})[\"']"
    )
    _CLOUD_TOKEN_PATTERN = re.compile(
        r"(?:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,255}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,})"
    )
    _HIGH_ENTROPY_PATTERN = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")
    _PLACEHOLDER_VALUES = {
        "your_api_key",
        "your_token",
        "your_secret",
        "your_password",
        "changeme",
        "change_me",
        "dummy",
        "example",
        "sample",
        "test",
        "password",
        "token",
        "secret",
    }

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._TEXT_EXTS:
                yield p

    @staticmethod
    def _looks_high_entropy(value: str) -> bool:
        if len(value) < 24:
            return False
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        return has_upper and has_lower and has_digit

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

                placeholder_hit = False
                secret_hit = False

                for m in self._KEY_VALUE_SECRET_PATTERN.finditer(stripped):
                    value = m.group(1).strip()
                    normalized = value.lower()
                    if normalized in self._PLACEHOLDER_VALUES or normalized.startswith(
                        "your_"
                    ):
                        placeholder_hit = True
                        continue
                    if self._CLOUD_TOKEN_PATTERN.search(
                        value
                    ) or self._looks_high_entropy(value):
                        secret_hit = True
                        break

                if not secret_hit and self._CLOUD_TOKEN_PATTERN.search(stripped):
                    secret_hit = True

                if not secret_hit and not placeholder_hit:
                    entropy_candidate = self._HIGH_ENTROPY_PATTERN.search(stripped)
                    if entropy_candidate and self._looks_high_entropy(
                        entropy_candidate.group(0)
                    ):
                        secret_hit = True

                if not (secret_hit or placeholder_hit):
                    continue

                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH if secret_hit else Severity.MEDIUM,
                        file_path=rel_path,
                        line=idx,
                        message=(
                            "秘密情報がハードコードされている可能性があります"
                            if secret_hit
                            else "プレースホルダ/ダミーの秘密値が残っている可能性があります"
                        ),
                    )
                )

        return records
