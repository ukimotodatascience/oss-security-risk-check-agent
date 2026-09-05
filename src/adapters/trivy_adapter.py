from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Dict, List
from src.mvp_models import Category, Finding

logger = logging.getLogger(__name__)


class TrivyAdapter:
    def __init__(self, cli_path: str = "trivy") -> None:
        self.cli_path = cli_path

    def run_scan_with_status(
        self, repo_url_or_path: str, max_output_bytes: int = 50 * 1024 * 1024
    ) -> tuple[List[Finding], bool]:
        """Trivy CLI を実行し (findings, success_flag) を返す。"""
        import tempfile

        try:
            is_url = repo_url_or_path.startswith(
                "http://"
            ) or repo_url_or_path.startswith("https://")
            scan_mode = "repo" if is_url else "fs"
            cmd = [self.cli_path, scan_mode, "--format", "json", repo_url_or_path]

            with (
                tempfile.TemporaryFile() as tmp_out,
                tempfile.TemporaryFile() as tmp_err,
            ):
                proc = subprocess.Popen(cmd, stdout=tmp_out, stderr=tmp_err, text=False)

                import time

                start_time = time.time()
                timed_out = False
                exceeded_size = False

                while proc.poll() is None:
                    if time.time() - start_time > 120:
                        timed_out = True
                        proc.kill()
                        break
                    total_size = tmp_out.tell() + tmp_err.tell()
                    if total_size > max_output_bytes:
                        exceeded_size = True
                        proc.kill()
                        break
                    time.sleep(0.1)

                proc.wait()
                tmp_err.seek(0)
                stderr_bytes = tmp_err.read(64 * 1024)

                if timed_out:
                    logger.warning("Trivy CLI timed out after 120s.")
                    return [], False

                total_size = tmp_out.tell() + tmp_err.tell()
                if exceeded_size or total_size > max_output_bytes:
                    logger.warning(
                        f"Trivy CLI output size ({total_size} bytes) exceeded limit ({max_output_bytes} bytes)."
                    )
                    return [], False

                if proc.returncode == 0 and tmp_out.tell() > 0:
                    tmp_out.seek(0)
                    data = json.load(tmp_out)
                    return self.parse_json(data), True

                stderr_text = (
                    stderr_bytes.decode("utf-8", errors="replace")
                    if stderr_bytes
                    else ""
                )
                logger.warning(
                    f"Trivy CLI exited with code {proc.returncode}: {stderr_text}"
                )
                return [], False
        except FileNotFoundError:
            logger.info("Trivy CLI not found in PATH.")
            return [], False
        except Exception as e:
            logger.error(f"Failed to run Trivy scan: {e}")
            return [], False

    def run_scan(
        self, repo_url_or_path: str, max_output_bytes: int = 50 * 1024 * 1024
    ) -> List[Finding]:
        """Trivy CLI を実行して Findings のリストを取得。"""
        findings, _ = self.run_scan_with_status(repo_url_or_path, max_output_bytes)
        return findings

    def parse_json(self, data: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        results = data.get("Results", [])

        for result in results:
            target = result.get("Target", "")

            # 1. 既知脆弱性 (Vulnerabilities)
            for vuln in result.get("Vulnerabilities", []):
                findings.append(
                    Finding(
                        category=Category.KNOWN_VULNERABILITIES,
                        source="trivy",
                        rule_id=vuln.get("VulnerabilityID", "CVE-UNKNOWN"),
                        severity=vuln.get("Severity", "MEDIUM").upper(),
                        title=vuln.get("Title")
                        or vuln.get("VulnerabilityID", "Vulnerability"),
                        target=target,
                        location=vuln.get("InstalledVersion", ""),
                        description=vuln.get("Description", ""),
                        remediation=f"Fixed in {vuln.get('FixedVersion', 'N/A')}",
                    )
                )

            # 2. Secret (Secrets)
            for secret in result.get("Secrets", []):
                rule_id = secret.get("RuleID", "SECRET-DETECTED")
                title = secret.get("Title", "Secret Detected")
                findings.append(
                    Finding(
                        category=Category.SECRETS,
                        source="trivy",
                        rule_id=rule_id,
                        severity=secret.get("Severity", "HIGH").upper(),
                        title=title,
                        target=target,
                        location=f"Line {secret.get('StartLine', 0)}",
                        description=f"Potential secret detected ({rule_id}: {title}). Match content redacted for security.",
                        remediation="Hardcoded secret should be removed and moved to environment variables or vault.",
                    )
                )

            # 3. Misconfiguration (設定セキュリティ)
            for misconf in result.get("Misconfigurations", []):
                findings.append(
                    Finding(
                        category=Category.MISCONFIGURATION,
                        source="trivy",
                        rule_id=misconf.get("ID", "MISCONF-DETECTED"),
                        severity=misconf.get("Severity", "MEDIUM").upper(),
                        title=misconf.get("Title", "Configuration Issue"),
                        target=target,
                        description=misconf.get("Description", ""),
                        remediation=misconf.get("Resolution", ""),
                    )
                )

        return findings

    def _get_mock_findings(self, repo_target: str) -> List[Finding]:
        """Trivy CLI が存在しない場合に安全なモック結果を返す"""
        return [
            Finding(
                category=Category.KNOWN_VULNERABILITIES,
                source="trivy",
                rule_id="CVE-2023-9999",
                severity="MEDIUM",
                title="Example Dependency Vulnerability (Mock)",
                target="package-lock.json",
                location="example-pkg@1.0.0",
                description="Mock vulnerability finding for demonstration.",
                remediation="Upgrade example-pkg to 1.0.1",
            )
        ]
