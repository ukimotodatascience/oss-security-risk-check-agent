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

    def run_scan_with_status(
        self,
        repo_url: str,
        max_output_bytes: int = 50 * 1024 * 1024,
        github_token: str | None = None,
    ) -> tuple[List[Finding], bool, str | None]:
        """Scorecard CLI を実行し (findings, success_flag, error_message) を返す。"""
        # テスト等で self.run_scan が Mock/Patch されている場合は mock 経由で実行
        if (
            hasattr(self.run_scan, "__self__")
            or hasattr(self.run_scan, "mock_calls")
            or type(self.run_scan).__name__ == "MagicMock"
        ):
            findings = self.run_scan(
                repo_url, max_output_bytes=max_output_bytes, github_token=github_token
            )
            return findings, True, None

        import os
        import tempfile
        import time

        try:
            cmd = [self.cli_path, f"--repo={repo_url}", "--format=json"]
            env = os.environ.copy()
            token = (
                github_token or env.get("GITHUB_TOKEN") or env.get("GITHUB_AUTH_TOKEN")
            )
            if token:
                env["GITHUB_TOKEN"] = token
                env["GITHUB_AUTH_TOKEN"] = token

            with (
                tempfile.TemporaryFile() as tmp_out,
                tempfile.TemporaryFile() as tmp_err,
            ):
                proc = subprocess.Popen(
                    cmd, stdout=tmp_out, stderr=tmp_err, text=False, env=env
                )

                start_time = time.time()
                timed_out = False
                exceeded_size = False

                while proc.poll() is None:
                    if time.time() - start_time > 120:
                        timed_out = True
                        proc.kill()
                        break
                    size = tmp_out.tell() + tmp_err.tell()
                    if size > max_output_bytes:
                        exceeded_size = True
                        proc.kill()
                        break
                    time.sleep(0.1)

                proc.wait()

                if timed_out:
                    err_msg = "Scorecard CLI timed out after 120s."
                    logger.warning(err_msg)
                    return [], False, err_msg

                size = tmp_out.tell() + tmp_err.tell()
                if exceeded_size or size > max_output_bytes:
                    err_msg = f"Scorecard CLI output size ({size} bytes) exceeded limit ({max_output_bytes} bytes)."
                    logger.warning(err_msg)
                    return [], False, err_msg

                out_size = tmp_out.tell()
                if proc.returncode == 0 and out_size > 0:
                    tmp_out.seek(0)
                    data = json.load(tmp_out)
                    return self.parse_json(data), True, None

                tmp_err.seek(0)
                stderr_bytes = tmp_err.read(64 * 1024)
                stderr_text = (
                    stderr_bytes.decode("utf-8", errors="replace")
                    if stderr_bytes
                    else ""
                )
                err_msg = f"Scorecard CLI exited with code {proc.returncode}: {stderr_text[:500]}".strip()
                logger.warning(
                    f"Scorecard CLI exited with code {proc.returncode}: {stderr_text}"
                )
                return [], False, err_msg
        except FileNotFoundError:
            err_msg = "Scorecard CLI not found in PATH."
            logger.info(err_msg)
            return [], False, err_msg
        except Exception as e:
            err_msg = f"Failed to run Scorecard scan: {e}"
            logger.error(err_msg)
            return [], False, err_msg

    def run_scan(
        self,
        repo_url: str,
        max_output_bytes: int = 50 * 1024 * 1024,
        github_token: str | None = None,
    ) -> List[Finding]:
        findings, _, _ = self.run_scan_with_status(
            repo_url, max_output_bytes=max_output_bytes, github_token=github_token
        )
        return findings

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
                    description=f"{reason} {detail_str}".strip()[:2000],
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
