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
    "Dependency-Update-Tool": Category.DEPENDENCIES,
    "Branch-Protection": Category.DEVELOPMENT,
    "Code-Review": Category.DEVELOPMENT,
    "CI-Tests": Category.DEVELOPMENT,
    "License": Category.DEVELOPMENT,
    "Dangerous-Workflow": Category.CICD,
    "Token-Permissions": Category.CICD,
    "Signed-Releases": Category.CICD,
    "Packaging": Category.CICD,
    "Webhooks": Category.CICD,
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

    def run_scan(
        self, repo_url: str, max_output_bytes: int = 50 * 1024 * 1024
    ) -> List[Finding]:
        import tempfile
        import time

        try:
            cmd = [self.cli_path, f"--repo={repo_url}", "--format=json"]
            with (
                tempfile.TemporaryFile() as tmp_out,
                tempfile.TemporaryFile() as tmp_err,
            ):
                proc = subprocess.Popen(cmd, stdout=tmp_out, stderr=tmp_err, text=False)

                start_time = time.time()
                timed_out = False
                exceeded_size = False

                while proc.poll() is None:
                    if time.time() - start_time > 120:
                        timed_out = True
                        proc.kill()
                        break
                    size = tmp_out.tell()
                    if size > max_output_bytes:
                        exceeded_size = True
                        proc.kill()
                        break
                    time.sleep(0.1)

                proc.wait()

                if timed_out:
                    logger.warning("Scorecard CLI timed out after 120s.")
                    return []

                size = tmp_out.tell()
                if exceeded_size or size > max_output_bytes:
                    logger.warning(
                        f"Scorecard CLI stdout size ({size} bytes) exceeded limit ({max_output_bytes} bytes)."
                    )
                    return []

                if proc.returncode == 0 and size > 0:
                    tmp_out.seek(0)
                    data = json.load(tmp_out)
                    return self.parse_json(data)

                tmp_err.seek(0)
                stderr_bytes = tmp_err.read()
                stderr_text = (
                    stderr_bytes.decode("utf-8", errors="replace")
                    if stderr_bytes
                    else ""
                )
                logger.warning(
                    f"Scorecard CLI exited with code {proc.returncode}: {stderr_text}"
                )
        except FileNotFoundError:
            logger.info("Scorecard CLI not found in PATH. Skipping Scorecard scan.")
            return []
        except Exception as e:
            logger.error(f"Failed to run Scorecard scan: {e}")

        return []

    def parse_json(self, data: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        checks = data.get("checks", [])

        for check in checks:
            name = check.get("name", "")
            raw_score = check.get("score", -1)  # -1 means disabled or unable to check
            reason = check.get("reason", "")
            details = check.get("details") or []

            cat = CHECK_CATEGORY_MAP.get(name)
            if cat is None:
                logger.debug(f"Unmapped Scorecard check skipped: {name}")
                continue

            if raw_score < 0:
                findings.append(
                    Finding(
                        category=cat,
                        source="scorecard",
                        rule_id=f"SCORECARD-{name.upper()}",
                        severity="INFO",
                        title=f"Scorecard: {name} (Unable to Evaluate)",
                        description=f"{reason} Check unable to evaluate or disabled.".strip(),
                        remediation=f"Enable or configure OpenSSF Scorecard check for {name}.",
                        raw_score=None,
                    )
                )
                continue

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
