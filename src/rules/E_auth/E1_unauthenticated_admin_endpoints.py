from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class E1UnauthenticatedAdminEndpointsRule:
    """認証不要の管理画面エンドポイントがないか"""

    rule_id = "E-1"
    category = "auth"
    title = "Unauthenticated Admin Endpoints"
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
    _ADMIN_ROUTE_PATTERN = re.compile(
        r"(?i)(?:route|router\.|app\.|blueprint\.|@\w+\.(?:get|post|put|delete|patch)|path\s*[:=]|location\s*[:=])"
        r"[^\n\r]*(?:/admin|/administrator|/manage|/management|/internal|/ops|/system)"
    )
    _AUTH_GUARD_PATTERN = re.compile(
        r"(?i)(?:login_required|auth_required|requires_auth|@permission_required|@roles_required|"
        r"authorize\(|has_permission\(|is_admin\b|current_user\b|Depends\([^\)]*auth|middleware[^\n\r]*auth|jwt_required)"
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
                if not stripped:
                    continue
                if not self._ADMIN_ROUTE_PATTERN.search(stripped):
                    continue

                window_start = max(0, idx - 4)
                window_end = min(len(lines), idx + 3)
                context = "\n".join(lines[window_start:window_end])
                if self._AUTH_GUARD_PATTERN.search(context):
                    continue

                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line=idx,
                        message="管理系エンドポイントに認証/認可ガードが見当たりません",
                    )
                )

        return records
