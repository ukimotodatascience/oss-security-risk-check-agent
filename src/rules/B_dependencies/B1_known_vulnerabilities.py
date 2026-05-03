from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import (
    collect_dependency_declarations,
    is_pinned,
)
from src.rules.B_dependencies.vuln_sources import VulnLookupService


class B1KnownVulnerabilitiesRule:
    """使用依存が既知CVEに該当していないか"""

    rule_id = "B-1"
    category = "dependencies"
    title = "Known Vulnerabilities"
    severity = Severity.MEDIUM

    def __init__(self) -> None:
        self._lookup = VulnLookupService()

    @staticmethod
    def _to_severity(score: float | None) -> Severity:
        if score is None:
            return Severity.MEDIUM
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        deps = collect_dependency_declarations(target)

        for dep in deps:
            if not is_pinned(dep):
                # カタログ条件: バージョン未固定で照合不能 → 注意
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=dep.file_path,
                        line=dep.line,
                        message=f"{dep.name} は既知脆弱性対象候補ですが、バージョン照合ができません（spec: '{dep.spec or '(none)'}'）。",
                    )
                )
                continue

            version = dep.spec.lstrip("=").strip()
            hits = self._lookup.lookup(dep.ecosystem, dep.name, version)
            for hit in hits:
                refs = (
                    f" refs: {', '.join(hit.references[:2])}" if hit.references else ""
                )
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=self._to_severity(hit.severity_score),
                        file_path=dep.file_path,
                        line=dep.line,
                        message=(
                            f"{dep.name} {dep.spec} は既知脆弱性に該当する可能性があります "
                            f"[{hit.source}:{hit.vuln_id}] {hit.summary[:160]}{refs}"
                        ),
                    )
                )

        return records
