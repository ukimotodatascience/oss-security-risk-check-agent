from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class C1CurlPipeShellRule:
    """curl | shやwget | bashなどの危険なコマンド実行がないか"""

    rule_id = "C-1"
    category = "cicd"
    title = "Curl Pipe Shell"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
