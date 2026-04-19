from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C5DangerousWorkflowTriggersRule:
    """危険なWorkflow Triggerがないか"""

    rule_id = "C-5"
    category = "cicd"
    title = "Dangerous Workflow Triggers"
    severity = Severity.MEDIUM

    _RISKY_EVENTS = (
        "issue_comment:",
        "pull_request_review_comment:",
        "repository_dispatch:",
    )
    _TRIGGER_GUARD_HINT = re.compile(
        r"contains\(\s*github\.event\.comment\.body\s*,\s*['\"]/(?:run|test|deploy)",
        re.IGNORECASE,
    )
    _SECRETS_PATTERN = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        workflows = target / ".github" / "workflows"
        if not workflows.exists():
            return records

        for wf in workflows.rglob("*.y*ml"):
            try:
                src = wf.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            lines = src.splitlines()
            risky_line = None
            for idx, line in enumerate(lines, start=1):
                low = line.strip().lower()
                if any(event in low for event in self._RISKY_EVENTS):
                    risky_line = idx
                    break

            if risky_line is None:
                continue

            has_secret_use = bool(self._SECRETS_PATTERN.search(src))
            has_comment_guard = bool(self._TRIGGER_GUARD_HINT.search(src))
            sev = (
                Severity.HIGH
                if has_secret_use and not has_comment_guard
                else Severity.MEDIUM
            )
            msg = (
                "低障壁イベントで機密付きジョブが走る可能性があります"
                if sev == Severity.HIGH
                else "低障壁イベントでワークフローが起動します。実行条件の制限を検討してください"
            )
            records.append(
                RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=sev,
                    file_path=str(wf.relative_to(target)),
                    line=risky_line,
                    message=msg,
                )
            )

        return records
