from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class F2SecretFilesCommittedRule:
    """秘密情報がコミットされていないか"""

    rule_id = "F-2"
    category = "secrets"
    title = "Secret Files Committed"
    severity = Severity.MEDIUM

    _SUSPICIOUS_SUFFIXES = {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".kdb",
        ".ovpn",
        ".pkcs8",
    }
    _SUSPICIOUS_NAME_PATTERNS = (
        re.compile(r"(?i)^credentials\.json$"),
        re.compile(r"(?i)^service-account.*\.json$"),
        re.compile(r"(?i)^id_(rsa|dsa|ecdsa|ed25519)$"),
        re.compile(r"(?i).*\b(?:secret|token|apikey|api_key|private_key)\b.*"),
    )
    _SAFE_NAME_HINTS = (
        ".pub",
        "example",
        "sample",
        "template",
        "dummy",
        "test",
    )

    def _is_suspicious(self, p: Path) -> bool:
        name = p.name.lower()
        if any(h in name for h in self._SAFE_NAME_HINTS):
            return False
        if p.suffix.lower() in self._SUSPICIOUS_SUFFIXES:
            return True
        return any(pat.match(name) for pat in self._SUSPICIOUS_NAME_PATTERNS)

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if ".git" in p.parts:
                continue
            if not self._is_suspicious(p):
                continue

            rel_path = str(p.relative_to(target))
            sev = (
                Severity.HIGH
                if p.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}
                else Severity.MEDIUM
            )
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=sev,
                    file_path=rel_path,
                    line=1,
                    message="秘密情報ファイルがリポジトリに含まれている可能性があります",
                )
            )

        return records
