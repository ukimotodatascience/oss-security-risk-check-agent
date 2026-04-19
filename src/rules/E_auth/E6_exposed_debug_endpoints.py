from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class E6ExposedDebugEndpointsRule:
    """認証不要のデバッグエンドポイントがないか"""

    rule_id = "E-6"
    category = "auth"
    title = "Exposed Debug Endpoints"
    severity = Severity.MEDIUM

    _TEXT_EXTS = {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".yml",
        ".yaml",
    }
    _DEBUG_ENDPOINT_PATTERN = re.compile(
        r"(?i)(?:route|router\.|app\.|@\w+\.(?:get|post)|path\s*[:=])[^\n\r]*(?:/debug|/__debug__|/actuator|/metrics|/trace|/pprof|/console|/graphql|/swagger|/api-docs|/docs)"
    )
    _AUTH_GUARD_PATTERN = re.compile(
        r"(?i)(?:login_required|auth_required|requires_auth|permission_required|roles_required|authorize\(|is_admin|request\.user|current_user|Depends\([^\)]*auth|middleware[^\n\r]*auth|jwt_required)"
    )
    _PROD_HINT_PATTERN = re.compile(r"(?i)(?:prod|production|release|staging|deploy)")

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
            file_has_prod_hint = bool(self._PROD_HINT_PATTERN.search(rel_path.lower()))

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                if not self._DEBUG_ENDPOINT_PATTERN.search(stripped):
                    continue

                window_start = max(0, idx - 4)
                window_end = min(len(lines), idx + 4)
                context = "\n".join(lines[window_start:window_end])
                if self._AUTH_GUARD_PATTERN.search(context):
                    continue

                sev = (
                    Severity.HIGH
                    if file_has_prod_hint or self._PROD_HINT_PATTERN.search(context)
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
                        message="デバッグ/運用向けエンドポイントが認証ガードなしで公開されている可能性があります",
                    )
                )

        return records
