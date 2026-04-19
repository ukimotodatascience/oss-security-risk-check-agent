from pathlib import Path
import re
from typing import List
from src.models import RiskRecord, Severity


class F4ExposedTokensInDocsRule:
    """ドキュメントにトークンが漏れていないか"""

    rule_id = "F-4"
    category = "secrets"
    title = "Exposed Tokens in Docs"
    severity = Severity.MEDIUM

    _DOC_EXTS = {".md", ".mdx", ".rst", ".txt", ".adoc"}
    _TOKEN_PATTERNS = (
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    )
    _PLACEHOLDER_HINTS = (
        "example",
        "sample",
        "dummy",
        "your_",
        "<token>",
        "xxxx",
    )

    def _iter_candidate_docs(self, target: Path):
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._DOC_EXTS:
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for file_path in self._iter_candidate_docs(target):
            try:
                lines = file_path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(target))
            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped:
                    continue

                lowered = stripped.lower()
                if any(h in lowered for h in self._PLACEHOLDER_HINTS):
                    continue

                if any(pat.search(stripped) for pat in self._TOKEN_PATTERNS):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=idx,
                            message="ドキュメント内に実トークンらしき文字列が含まれています",
                        )
                    )

        return records
