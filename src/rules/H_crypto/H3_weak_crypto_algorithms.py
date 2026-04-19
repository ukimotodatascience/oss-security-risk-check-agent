from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class H3WeakCryptoAlgorithmsRule:
    """脆弱な暗号アルゴリズムがないか"""

    rule_id = "H-3"
    category = "crypto"
    title = "Weak Crypto Algorithms"
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
        ".txt",
    }
    _ALGORITHM_PATTERNS = (
        ("MD5", re.compile(r"\bmd5\b", re.IGNORECASE), Severity.HIGH),
        (
            "SHA1",
            re.compile(r"\b(?:sha1|sha-1)\b", re.IGNORECASE),
            Severity.MEDIUM,
        ),
        (
            "DES",
            re.compile(r"\b(?:des|3des|tripledes)\b", re.IGNORECASE),
            Severity.HIGH,
        ),
        ("RC4", re.compile(r"\brc4\b", re.IGNORECASE), Severity.HIGH),
    )
    _COMMENT_ONLY = re.compile(r"^\s*(?:#|//|\*)")

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
                if not stripped or self._COMMENT_ONLY.search(stripped):
                    continue

                for alg_name, pattern, sev in self._ALGORITHM_PATTERNS:
                    if not pattern.search(stripped):
                        continue
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=sev,
                            file_path=rel_path,
                            line=idx,
                            message=f"脆弱/非推奨の暗号アルゴリズム {alg_name} の利用が検出されました",
                        )
                    )
                    break

        return records
