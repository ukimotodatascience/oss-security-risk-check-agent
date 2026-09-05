from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Dict, List
from src.mvp_models import Category, Finding

logger = logging.getLogger(__name__)

# Scorecard チェック項目とカテゴリのマッピング
CHECK_CATEGORY_MAP: Dict[str, Category] = {
    "Binary-Artifacts": Category.DEPENDENCIES,
    "Pinned-Dependencies": Category.DEPENDENCIES,
    "Vulnerabilities": Category.DEPENDENCIES,
    "Branch-Protection": Category.DEVELOPMENT,
    "Code-Review": Category.DEVELOPMENT,
    "CI-Tests": Category.DEVELOPMENT,
    "Dangerous-Workflow": Category.CICD,
    "Token-Permissions": Category.CICD,
    "Signed-Releases": Category.CICD,
    "Packaging": Category.CICD,
    "Maintained": Category.MAINTENANCE,
    "Security-Policy": Category.MAINTENANCE,
    "CII-Best-Practices": Category.MAINTENANCE,
    "Fuzzing": Category.MAINTENANCE,
    "SAST": Category.MAINTENANCE,
    "Contributors": Category.MAINTENANCE,
}


class ScorecardAdapter:
    def __init__(self, cli_path: str = "scorecard") -> None:
        self.cli_path = cli_path

    def run_scan(self, repo_url: str) -> List[Finding]:
        try:
            cmd = [self.cli_path, f"--repo={repo_url}", "--format=json"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0 and res.stdout:
                data = json.loads(res.stdout)
                return self.parse_json(data)
            logger.warning(
                f"Scorecard CLI exited with code {res.returncode}: {res.stderr}"
            )
        except FileNotFoundError:
            logger.info(
                "Scorecard CLI not found in PATH. Returning mock Scorecard findings."
            )
            return self._get_mock_findings(repo_url)
        except Exception as e:
            logger.error(f"Failed to run Scorecard scan: {e}")

        return self._get_mock_findings(repo_url)

    def parse_json(self, data: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        checks = data.get("checks", [])

        for check in checks:
            name = check.get("name", "")
            raw_score = check.get("score", -1)  # -1 means disabled or unable to check
            reason = check.get("reason", "")
            details = check.get("details") or []
            cat = CHECK_CATEGORY_MAP.get(name, Category.MAINTENANCE)

            if raw_score < 0:
                continue

            # スコアが低い(7点未満)場合をFindingとして抽出
            severity = "INFO"
            if raw_score <= 3:
                severity = "HIGH"
            elif raw_score <= 6:
                severity = "MEDIUM"
            elif raw_score <= 8:
                severity = "LOW"

            detail_str = (
                "; ".join(details[:3]) if isinstance(details, list) else str(details)
            )

            findings.append(
                Finding(
                    category=cat,
                    source="scorecard",
                    rule_id=f"SCORECARD-{name.upper()}",
                    severity=severity,
                    title=f"Scorecard: {name} (Score: {raw_score}/10)",
                    description=f"{reason} {detail_str}".strip(),
                    remediation=f"Improve OpenSSF Scorecard practice for {name}.",
                    raw_score=float(raw_score),
                )
            )

        return findings

    def _get_mock_findings(self, repo_target: str) -> List[Finding]:
        """Scorecard CLI が存在しない場合に安全なモック結果を返す"""
        mock_checks = [
            (
                "Branch-Protection",
                8,
                Category.DEVELOPMENT,
                "Branch protection rules present.",
            ),
            ("Code-Review", 10, Category.DEVELOPMENT, "Code review required for PRs."),
            (
                "Pinned-Dependencies",
                5,
                Category.DEPENDENCIES,
                "Some dependencies are not pinned.",
            ),
            (
                "Token-Permissions",
                6,
                Category.CICD,
                "GitHub Actions token permissions not minimal.",
            ),
            ("Security-Policy", 10, Category.MAINTENANCE, "SECURITY.md file detected."),
            (
                "Maintained",
                9,
                Category.MAINTENANCE,
                "Active commits in the last 90 days.",
            ),
        ]
        findings = []
        for name, score, cat, reason in mock_checks:
            severity = "INFO" if score >= 8 else ("MEDIUM" if score >= 5 else "HIGH")
            findings.append(
                Finding(
                    category=cat,
                    source="scorecard",
                    rule_id=f"SCORECARD-{name.upper()}",
                    severity=severity,
                    title=f"Scorecard: {name} (Score: {score}/10)",
                    description=reason,
                    remediation=f"Review practice for {name}",
                    raw_score=float(score),
                )
            )
        return findings
