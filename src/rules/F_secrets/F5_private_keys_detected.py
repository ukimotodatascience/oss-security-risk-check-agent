from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class F5PrivateKeysDetectedRule:
    """秘密鍵が検出されていないか"""

    rule_id = "F-5"
    category = "secrets"
    title = "Private Keys Detected"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {
        ".pem",
        ".key",
        ".txt",
        ".env",
        ".cfg",
        ".conf",
        ".ini",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".md",
        ".py",
        ".js",
        ".ts",
        ".sh",
    }
    _PRIVATE_KEY_BLOCK_PATTERN = re.compile(
        r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file():
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
                if self._PRIVATE_KEY_BLOCK_PATTERN.search(line):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            file_path=rel_path,
                            line=idx,
                            message="PEM 形式の秘密鍵ブロックが検出されました",
                        )
                    )
                    break

        return records
