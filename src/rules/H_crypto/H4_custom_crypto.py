from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class H4CustomCryptoRule:
    """独自暗号化がないか"""

    rule_id = "H-4"
    category = "crypto"
    title = "Custom Crypto"
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
        ".sh",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".md",
    }
    _CUSTOM_CRYPTO_PATTERNS = (
        re.compile(
            r"\b(?:custom|home\s*grown|proprietary)\s+(?:crypto|cipher|encryption)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\broll\s+your\s+own\s+crypto\b", re.IGNORECASE),
        re.compile(
            r"\b(?:xor|caesar|vigenere)\s*(?:cipher|encrypt|decrypt)?\b", re.IGNORECASE
        ),
        re.compile(r"\bdef\s+(?:encrypt|decrypt|cipher)\w*\s*\(", re.IGNORECASE),
    )
    _SAFE_LIB_HINT = re.compile(
        r"\b(?:cryptography|openssl|libsodium|pyca|bcrypt|argon2|aesgcm|fernet)\b",
        re.IGNORECASE,
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._TEXT_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for file_path in self._iter_candidate_files(target):
            try:
                src = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            lines = src.splitlines()
            has_safe_lib_hint = self._SAFE_LIB_HINT.search(src) is not None
            rel_path = str(file_path.relative_to(target))

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not any(
                    pattern.search(stripped) for pattern in self._CUSTOM_CRYPTO_PATTERNS
                ):
                    continue

                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH
                        if not has_safe_lib_hint
                        else Severity.MEDIUM,
                        file_path=rel_path,
                        line=idx,
                        message=(
                            "標準ライブラリ外の独自暗号実装の可能性があります"
                            if not has_safe_lib_hint
                            else "独自暗号に見える実装が検出されました（検証済みライブラリ利用を推奨）"
                        ),
                    )
                )

        return records
