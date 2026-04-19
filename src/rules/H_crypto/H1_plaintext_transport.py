from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class H1PlaintextTransportRule:
    """平文トランスポートがないか"""

    rule_id = "H-1"
    category = "crypto"
    title = "Plaintext Transport"
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
        ".env",
        ".ini",
        ".conf",
        ".yml",
        ".yaml",
        ".json",
        ".md",
        ".txt",
        ".rst",
    }
    _PLAINTEXT_URL_PATTERN = re.compile(
        r"\b(?:http|ws|ftp)://[^\s\"'<>]+", re.IGNORECASE
    )
    _LOCAL_URL_PATTERN = re.compile(
        r"^(?:http|ws)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])", re.IGNORECASE
    )
    _SENSITIVE_HINT = re.compile(
        r"\b(?:token|secret|password|passwd|session|auth|authorization|apikey|api_key|credential)\b",
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
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                for match in self._PLAINTEXT_URL_PATTERN.finditer(stripped):
                    url = match.group(0)
                    if self._LOCAL_URL_PATTERN.search(url):
                        continue

                    severity = (
                        Severity.HIGH
                        if self._SENSITIVE_HINT.search(stripped)
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
                            message=(
                                "機密データを平文プロトコルで送信する可能性があります"
                                if severity == Severity.HIGH
                                else "平文プロトコル (HTTP/WS/FTP) の URL が検出されました"
                            ),
                        )
                    )

        return records
