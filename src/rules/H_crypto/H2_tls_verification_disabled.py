from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class H2TLSVerificationDisabledRule:
    """TLS検証が無効になっていないか"""

    rule_id = "H-2"
    category = "crypto"
    title = "TLS Verification Disabled"
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
        ".env",
        ".md",
    }
    _DISABLE_PATTERNS = (
        re.compile(r"\bverify\s*=\s*False\b"),
        re.compile(r"\bssl\s*=\s*False\b"),
        re.compile(r"\bcheck_hostname\s*=\s*False\b"),
        re.compile(r"\binsecureSkipVerify\s*:\s*true\b", re.IGNORECASE),
        re.compile(r"\brejectUnauthorized\s*:\s*false\b", re.IGNORECASE),
        re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0[\"']?\b"),
        re.compile(r"\bcurl\b[^\n]*\s(?:-k|--insecure)\b", re.IGNORECASE),
        re.compile(r"\bwget\b[^\n]*\s--no-check-certificate\b", re.IGNORECASE),
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
                if not any(
                    pattern.search(stripped) for pattern in self._DISABLE_PATTERNS
                ):
                    continue

                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=idx,
                        message="TLS 証明書検証を無効化する設定が検出されました",
                    )
                )

        return records
