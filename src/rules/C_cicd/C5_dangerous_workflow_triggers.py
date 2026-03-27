from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C5DangerousWorkflowTriggersRule:
    """危険なWorkflow Triggerがないか"""

    rule_id = "C-5"
    category = "cicd"
    title = "Dangerous Workflow Triggers"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
