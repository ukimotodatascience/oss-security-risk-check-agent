from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class F6CloudCredentialsDetectedRule:
    """クラウドの秘密情報が検出されていないか"""

    rule_id = "F-6"
    category = "secrets"
    title = "Cloud Credentials Detected"
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
        ".sh",
        ".txt",
        ".md",
    }
    _CLOUD_PATTERNS = (
        ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        (
            "AWS Secret Access Key",
            re.compile(
                r"(?i)\baws_secret_access_key\b\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?"
            ),
        ),
        (
            "GCP API Key",
            re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        ),
        (
            "GCP Service Account",
            re.compile(r"(?i)\btype\b\s*[:=]\s*[\"']service_account[\"']"),
        ),
        (
            "Azure Storage Key / SAS",
            re.compile(
                r"(?i)\b(?:AccountKey|SharedAccessSignature|sig)\b\s*[:=]\s*[\"']?[A-Za-z0-9%/+_=\-]{20,}[\"']?"
            ),
        ),
    )
    _PLACEHOLDER_HINTS = (
        "example",
        "sample",
        "dummy",
        "your_",
        "changeme",
        "<",
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
                lowered = stripped.lower()
                if any(h in lowered for h in self._PLACEHOLDER_HINTS):
                    continue

                for label, pat in self._CLOUD_PATTERNS:
                    if pat.search(stripped):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=idx,
                                message=f"{label} 形式のクレデンシャルが露出している可能性があります",
                            )
                        )
                        break

        return records
