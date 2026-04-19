from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class C4UntrustedCheckoutRule:
    """外部PRや外部コードを取り組む構成になっていないか"""

    rule_id = "C-4"
    category = "cicd"
    title = "Untrusted Checkout"
    severity = Severity.MEDIUM

    _EVENT_PATTERN = re.compile(r"^\s*pull_request_target\s*:\s*$")
    _USES_CHECKOUT_PATTERN = re.compile(r"^\s*uses\s*:\s*actions/checkout@")
    _REF_FROM_PR_PATTERN = re.compile(
        r"\$\{\{\s*github\.event\.pull_request\.(?:head\.sha|head\.ref)\s*\}\}"
    )
    _SECRETS_PATTERN = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        workflows = target / ".github" / "workflows"
        if not workflows.exists():
            return records

        for wf in workflows.rglob("*.y*ml"):
            try:
                lines = wf.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            has_pr_target = any(self._EVENT_PATTERN.search(line) for line in lines)
            has_checkout = any(
                self._USES_CHECKOUT_PATTERN.search(line) for line in lines
            )
            has_untrusted_ref = any(
                self._REF_FROM_PR_PATTERN.search(line) for line in lines
            )
            has_secrets = any(self._SECRETS_PATTERN.search(line) for line in lines)

            if not has_checkout:
                continue

            if has_pr_target and (has_untrusted_ref or has_secrets):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=str(wf.relative_to(target)),
                        line=1,
                        message="pull_request_target で非信頼 PR コードを checkout し、機密に触れる可能性があります",
                    )
                )

        return records
