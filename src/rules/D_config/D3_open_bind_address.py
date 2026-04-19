from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class D3OpenBindAddressRule:
    """危険なバインドアドレスがないか"""

    rule_id = "D-3"
    category = "config"
    title = "Open Bind Address"
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
        ".sh",
    }
    _OPEN_BIND_PATTERNS = (
        re.compile(
            r"(?i)\b(?:host|bind|listen|address|addr)\b\s*[:=]\s*[\"']?(?:0\.0\.0\.0|::)[\"']?"
        ),
        re.compile(r"(?i)\b--host(?:=|\s+)(?:0\.0\.0\.0|::)\b"),
        re.compile(
            r"(?i)\b(?:uvicorn|flask\s+run|gunicorn|node|npm\s+run)\b[^\n\r]*\b(?:0\.0\.0\.0|::)\b"
        ),
    )

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            if p.name.lower() in {
                "dockerfile",
                "docker-compose.yml",
                "docker-compose.yaml",
            }:
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

                if any(pat.search(stripped) for pat in self._OPEN_BIND_PATTERNS):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="サービスが 0.0.0.0 / :: にバインドされ、過剰公開となる可能性があります",
                        )
                    )

        return records
