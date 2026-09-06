from pathlib import Path
from typing import List, Protocol

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import (
    collect_dependency_declarations,
    is_pinned,
)
from src.rules.B_dependencies.vuln_sources import VulnHit, VulnLookupService


class VulnLookup(Protocol):
    def lookup(self, ecosystem: str, name: str, version: str) -> List[VulnHit]: ...
    def bulk_lookup(
        self, ecosystem: str, dependencies: List[tuple[str, str]]
    ) -> dict[tuple[str, str], List[VulnHit]]: ...


class B1KnownVulnerabilitiesRule:
    """使用依存が既知CVEに該当していないか"""

    rule_id = "B-1"
    category = "dependencies"
    title = "Known Vulnerabilities"
    severity = Severity.MEDIUM

    def __init__(self, lookup: VulnLookup | None = None) -> None:
        self._lookup = lookup or VulnLookupService()

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

    def evaluate(self, target: Path, max_records: int = 500) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        deps = collect_dependency_declarations(target)

        deps_truncated = False
        if len(deps) > max_records:
            deps = deps[:max_records]
            deps_truncated = True

        pinned_deps_by_eco: dict[str, list[tuple[str, str]]] = {}

        for dep in deps:
            if len(records) >= max_records:
                deps_truncated = True
                break
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
            pinned_deps_by_eco.setdefault(dep.ecosystem, []).append((dep, version))

        for ecosystem, dep_list in pinned_deps_by_eco.items():
            if len(records) >= max_records:
                deps_truncated = True
                break
            if hasattr(self._lookup, "bulk_lookup"):
                query_list = [(dep.name, version) for dep, version in dep_list]
                bulk_results = self._lookup.bulk_lookup(ecosystem, query_list)
            else:
                bulk_results = {
                    (dep.name, version): self._lookup.lookup(
                        ecosystem, dep.name, version
                    )
                    for dep, version in dep_list
                }

            for dep, version in dep_list:
                if len(records) >= max_records:
                    deps_truncated = True
                    break
                hits = bulk_results.get((dep.name, version), [])
                for hit in hits:
                    if len(records) >= max_records:
                        deps_truncated = True
                        break
                    refs = (
                        f" refs: {', '.join(hit.references[:2])}"
                        if hit.references
                        else ""
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

        if deps_truncated or len(records) >= max_records:
            if len(records) >= max_records:
                records = records[: max_records - 1]
            trunc_rec = RiskRecord(
                rule_id=self.rule_id,
                category=self.category,
                title=self.title,
                severity=Severity.LOW,
                file_path="dependencies",
                line=1,
                message=f"B-1: 依存関係の照会件数が上限 ({max_records}件) に達したため、残りの依存関係照会を打ち切りました。",
            )
            records.append(trunc_rec)

        return records
