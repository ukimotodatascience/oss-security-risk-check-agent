from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class D2DebugEnabledRule:
    """デバッグ用ログ出力がないか"""

    rule_id = "D-2"
    category = "config"
    title = "Debug Enabled"
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
    _DEBUG_ENABLED_PATTERNS = (
        re.compile(r"(?i)\bdebug\b\s*[:=]\s*(?:1|true|yes|on)\b"),
        re.compile(r"(?i)\bflask_debug\b\s*[:=]\s*(?:1|true|yes|on)\b"),
        re.compile(r"(?i)\bdjango_debug\b\s*[:=]\s*(?:1|true|yes|on)\b"),
        re.compile(r"(?i)\bapp_debug\b\s*[:=]\s*(?:1|true|yes|on)\b"),
    )
    _PRODUCTION_HINT = re.compile(
        r"(?i)\b(?:prod|production|stg|stage|release)\b|\benvironment\b\s*[:=]\s*(?:prod|production)\b"
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
            lowered_path = rel_path.lower()
            file_has_prod_hint = "prod" in lowered_path or "production" in lowered_path

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                if not any(
                    pat.search(stripped) for pat in self._DEBUG_ENABLED_PATTERNS
                ):
                    continue

                line_has_prod_hint = bool(self._PRODUCTION_HINT.search(stripped))
                sev = (
                    Severity.HIGH
                    if file_has_prod_hint or line_has_prod_hint
                    else Severity.MEDIUM
                )
                msg = (
                    "本番相当の設定でデバッグが有効になっている可能性があります"
                    if sev == Severity.HIGH
                    else "デバッグ設定が有効です。運用環境で無効化されているか確認してください"
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
