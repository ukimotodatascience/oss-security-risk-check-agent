from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class E4InsecureSessionConfigRule:
    """危険なセッション設定がないか"""

    rule_id = "E-4"
    category = "auth"
    title = "Insecure Session Config"
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
    }
    _SECURE_FALSE = re.compile(
        r"(?i)(?:session|cookie)[^\n\r]*(?:secure|cookie_secure)\s*[:=]\s*(?:false|0|off|no)"
    )
    _HTTPONLY_FALSE = re.compile(
        r"(?i)(?:session|cookie)[^\n\r]*(?:httponly|http_only)\s*[:=]\s*(?:false|0|off|no)"
    )
    _SAMESITE_NONE = re.compile(
        r"(?i)(?:session|cookie)[^\n\r]*samesite\s*[:=]\s*[\"']?none[\"']?"
    )
    _FIXATION_HINT = re.compile(
        r"(?i)(?:session[_-]?id\s*[:=]|set[_-]?cookie\([^\)]*session|regenerate|rotate|renew)"
    )
    _SESSION_CONFIG_HINT = re.compile(
        r"(?i)(?:session|cookie|session_cookie|sessionid|session_id)"
    )
    _HTTPS_HINT = re.compile(r"(?i)\bhttps\b|\bproduction\b|\bsecure\b")

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
            src = "\n".join(lines)
            has_fixation_control = bool(self._FIXATION_HINT.search(src))
            file_has_https_hint = bool(self._HTTPS_HINT.search(rel_path.lower()))

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if self._SECURE_FALSE.search(stripped):
                    sev = (
                        Severity.HIGH
                        if file_has_https_hint or self._HTTPS_HINT.search(stripped)
                        else Severity.MEDIUM
                    )
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=sev,
                            file_path=rel_path,
                            line=idx,
                            message="セッションクッキーの Secure 属性が無効化されています",
                        )
                    )
                elif self._HTTPONLY_FALSE.search(stripped):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="セッションクッキーの HttpOnly 属性が無効化されています",
                        )
                    )
                elif self._SAMESITE_NONE.search(stripped):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=idx,
                            message="SameSite 設定が緩く、CSRF リスクが高まる可能性があります",
                        )
                    )

            if self._SESSION_CONFIG_HINT.search(src) and not has_fixation_control:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.LOW,
                        file_path=rel_path,
                        line=1,
                        message="セッション固定対策（IDローテーション等）が明示されていない可能性があります",
                    )
                )

        return records
