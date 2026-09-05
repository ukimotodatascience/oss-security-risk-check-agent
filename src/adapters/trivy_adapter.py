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

    def run_scan(self, repo_url_or_path: str) -> List[Finding]:
        """Trivy CLI を実行して Findings のリストを取得。利用不可の場合はダミーまたは空リスト。"""
        try:
            is_url = repo_url_or_path.startswith(
                "http://"
            ) or repo_url_or_path.startswith("https://")
            scan_mode = "repo" if is_url else "fs"
            cmd = [self.cli_path, scan_mode, "--format", "json", repo_url_or_path]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if res.returncode == 0 and res.stdout:
                data = json.loads(res.stdout)
                return self.parse_json(data)
            logger.warning(f"Trivy CLI exited with code {res.returncode}: {res.stderr}")
        except FileNotFoundError:
            logger.info("Trivy CLI not found in PATH.")
            return []
        except Exception as e:
            logger.error(f"Failed to run Trivy scan: {e}")

        return []

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
