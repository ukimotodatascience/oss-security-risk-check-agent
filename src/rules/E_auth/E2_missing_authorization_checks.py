from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class E2MissingAuthorizationChecksRule:
    """認証不要のエンドポイントがないか"""

    rule_id = "E-2"
    category = "auth"
    title = "Missing Authorization Checks"
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
    }
    _ROUTE_PATTERN = re.compile(
        r"(?i)(?:@\w+\.(?:get|post|put|patch|delete)|app\.(?:get|post|put|patch|delete)|router\.(?:get|post|put|patch|delete)|@app\.route|@router\.api_route)"
    )
    _ID_ACCESS_PATTERN = re.compile(
        r"(?i)(?:\{[^\}]*id\}|\b[a-z_]*id\b\s*(?:=|:)|find_by_id\(|get_by_id\(|where\([^\)]*id|filter\([^\)]*id|/users?/|/accounts?/|/orders?/|/projects?/|/tenants?/|/orgs?/|/repos?/|/items?/|/resources?/|/profile/)"
    )
    _AUTHZ_PATTERN = re.compile(
        r"(?i)(?:authorize\(|permission|required|has_permission|has_role|role_required|policy\.|is_owner|owner_id|current_user\.(?:id|role)|request\.user|scope|acl|can_\w+\(|deny_unless|forbidden|403)"
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
                if not (
                    self._ROUTE_PATTERN.search(stripped)
                    or self._ID_ACCESS_PATTERN.search(stripped)
                ):
                    continue

                window_start = max(0, idx - 5)
                window_end = min(len(lines), idx + 6)
                context = "\n".join(lines[window_start:window_end])
                if not self._ID_ACCESS_PATTERN.search(context):
                    continue
                if self._AUTHZ_PATTERN.search(context):
                    continue

                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line=idx,
                        message="IDベースのリソースアクセスに認可チェックが見当たりません（IDORの可能性）",
                    )
                )

        return records
