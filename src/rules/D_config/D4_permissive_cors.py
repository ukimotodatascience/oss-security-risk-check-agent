from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class D4PermissiveCORSRule:
    """危険なCORS設定がないか"""

    rule_id = "D-4"
    category = "config"
    title = "Permissive CORS"
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
    _WILDCARD_CORS_PATTERNS = (
        re.compile(r"(?i)access-control-allow-origin\s*[:=]\s*[\"']?\*[\"']?"),
        re.compile(r"(?i)\borigin\s*[:=]\s*[\"']\*[\"']"),
        re.compile(r"(?i)\ballowed_origins?\s*[:=]\s*\[[^\]]*[\"']\*[\"']"),
        re.compile(r"(?i)\bcors\b[^\n\r]*(?:allow|origin)[^\n\r]*\*"),
    )
    _CREDENTIALS_PATTERN = re.compile(
        r"(?i)access-control-allow-credentials\s*[:=]\s*(?:true|1)|\bcredentials\s*[:=]\s*(?:true|1)"
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if p.name.lower() in {
                "dockerfile",
                "docker-compose.yml",
                "docker-compose.yaml",
                "nginx.conf",
            }:
                yield p
                continue
            if p.suffix.lower() in self._TEXT_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for file_path in self._iter_candidate_files(target):
            try:
                src = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(target))
            has_credentials = bool(self._CREDENTIALS_PATTERN.search(src))
            lines = src.splitlines()

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if any(pat.search(stripped) for pat in self._WILDCARD_CORS_PATTERNS):
                    sev = Severity.HIGH if has_credentials else Severity.MEDIUM
                    msg = (
                        "CORS がワイルドカード許可かつ credentials 有効の可能性があります"
                        if sev == Severity.HIGH
                        else "CORS 設定が過度に広く（ワイルドカード）許可されています"
                    )
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=sev,
                            file_path=rel_path,
                            line=idx,
                            message=msg,
                        )
                    )

        return records
