from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class D6MissingSecurityHeadersRule:
    """セキュリティヘッダーの不足がないか"""

    rule_id = "D-6"
    category = "config"
    title = "Missing Security Headers"
    severity = Severity.MEDIUM

    _TARGET_FILE_PATTERNS = (
        re.compile(r"(?i)(?:nginx|apache|httpd|traefik|caddy)"),
        re.compile(r"(?i)(?:settings|config|security|headers?)"),
    )
    _TEXT_EXTS = {
        ".conf",
        ".ini",
        ".cfg",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".py",
        ".js",
        ".ts",
    }
    _HEADER_PATTERNS = {
        "csp": re.compile(r"(?i)content-security-policy|\bcsp\b"),
        "hsts": re.compile(r"(?i)strict-transport-security|\bhsts\b|includeSubDomains"),
        "xcto": re.compile(r"(?i)x-content-type-options|nosniff"),
        "xfo": re.compile(r"(?i)x-frame-options|frame-ancestors|deny|sameorigin"),
        "referrer": re.compile(r"(?i)referrer-policy"),
    }

    def _iter_candidate_files(self, target: Path):
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            name = p.name.lower()
            if name in {"dockerfile", "nginx.conf", "caddyfile"}:
                yield p
                continue
            if p.suffix.lower() not in self._TEXT_EXTS:
                continue
            full = str(p).lower()
            if any(pat.search(full) for pat in self._TARGET_FILE_PATTERNS):
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        scanned = 0
        observed = {k: False for k in self._HEADER_PATTERNS}

        for file_path in self._iter_candidate_files(target):
            try:
                src = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            scanned += 1
            for key, pat in self._HEADER_PATTERNS.items():
                if pat.search(src):
                    observed[key] = True

        if scanned == 0:
            return records

        missing = [
            ("csp", "Content-Security-Policy (CSP)"),
            ("hsts", "Strict-Transport-Security (HSTS)"),
            ("xcto", "X-Content-Type-Options"),
            ("xfo", "X-Frame-Options / frame-ancestors"),
            ("referrer", "Referrer-Policy"),
        ]
        missing_names = [name for key, name in missing if not observed[key]]
        if missing_names:
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path="(config)",
                    line=1,
                    message=(
                        "推奨セキュリティヘッダの設定が不足している可能性があります: "
                        + ", ".join(missing_names)
                    ),
                )
            )

        return records
