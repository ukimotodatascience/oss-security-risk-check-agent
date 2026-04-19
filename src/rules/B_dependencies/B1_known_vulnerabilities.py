from pathlib import Path
from typing import List

from src.models import RiskRecord, Severity
from src.rules.B_dependencies._dependency_utils import (
    collect_dependency_declarations,
    is_pinned,
    parse_version_tuple,
)


class B1KnownVulnerabilitiesRule:
    """使用依存が既知CVEに該当していないか"""

    rule_id = "B-1"
    category = "dependencies"
    title = "Known Vulnerabilities"
    severity = Severity.MEDIUM

    # 実運用では脆弱性DB連携が望ましいため、ここでは簡易シグネチャで判定する。
    _VULN_THRESHOLDS = {
        # package: (fixed_version_exclusive, severity_if_hit)
        "pyyaml": ((6, 0), Severity.HIGH),
        "jinja2": ((3, 1, 3), Severity.HIGH),
        "urllib3": ((2, 2, 2), Severity.HIGH),
        "requests": ((2, 32, 3), Severity.MEDIUM),
        "lodash": ((4, 17, 21), Severity.HIGH),
        "minimist": ((1, 2, 8), Severity.HIGH),
        "axios": ((1, 6, 0), Severity.MEDIUM),
    }

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        deps = collect_dependency_declarations(target)

        for dep in deps:
            vuln = self._VULN_THRESHOLDS.get(dep.name)
            if not vuln:
                continue

            fixed_ver, hit_severity = vuln
            ver = parse_version_tuple(dep.spec)
            rel = dep.file_path

            if ver is None:
                # カタログ条件: バージョン未固定で照合不能 → 注意
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel,
                        line=dep.line,
                        message=f"{dep.name} は既知脆弱性対象候補ですが、バージョン照合ができません（spec: '{dep.spec or '(none)'}'）。",
                    )
                )
                continue

            if ver < fixed_ver:
                fixed_label = ".".join([str(x) for x in fixed_ver])
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=hit_severity,
                        file_path=rel,
                        line=dep.line,
                        message=f"{dep.name} {dep.spec} は既知脆弱性の影響を受ける可能性があります（修正目安: < {fixed_label}）。",
                    )
                )
            elif not is_pinned(dep):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.LOW,
                        file_path=rel,
                        line=dep.line,
                        message=f"{dep.name} は既知脆弱性対象になりやすいパッケージです。バージョン固定を推奨します（spec: '{dep.spec}'）。",
                    )
                )

        return records
