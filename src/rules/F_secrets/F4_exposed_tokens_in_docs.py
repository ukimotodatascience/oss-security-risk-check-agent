from pathlib import Path
from typing import List
from src.models import RiskRecord, Severity


class F4ExposedTokensInDocsRule:
    """ドキュメントにトークンが漏れていないか"""

    rule_id = "F-4"
    category = "secrets"
    title = "Exposed Tokens in Docs"
    severity = Severity.MEDIUM

    def evaluate(self, target: Path) -> List[RiskRecord]:
        return []
