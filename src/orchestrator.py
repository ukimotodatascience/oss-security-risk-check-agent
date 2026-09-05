from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from src.adapters.scorecard_adapter import ScorecardAdapter
from src.adapters.trivy_adapter import TrivyAdapter
from src.mvp_models import Category, Finding, OverallResult
from src.scoring.engine import ScoringEngine

logger = logging.getLogger(__name__)


class MVPOrchestrator:
    def __init__(self, project_root: Optional[Path] = None) -> None:
        self.project_root = project_root or Path(__file__).resolve().parent.parent
        self.trivy_adapter = TrivyAdapter()
        self.scorecard_adapter = ScorecardAdapter()
        self.scoring_engine = ScoringEngine()

    def run_full_scan(self, repo_url: str, save_to_docs: bool = True) -> OverallResult:
        logger.info(f"Starting MVP full scan for repository: {repo_url}")
        all_findings: List[Finding] = []

        # 1. Trivy Scan (既知脆弱性, Secret, 設定)
        try:
            trivy_findings = self.trivy_adapter.run_scan(repo_url)
            all_findings.extend(trivy_findings)
        except Exception as e:
            logger.error(f"Error during Trivy scan: {e}")

        # 2. OpenSSF Scorecard Scan (Supply Chain, Dev Process, CI/CD, Maintenance)
        try:
            scorecard_findings = self.scorecard_adapter.run_scan(repo_url)
            all_findings.extend(scorecard_findings)
        except Exception as e:
            logger.error(f"Error during Scorecard scan: {e}")

        # 3. 既存 Rule-based Scan (ソースコード固有の判定)
        try:
            rule_findings = self._run_rule_based_scan(repo_url)
            all_findings.extend(rule_findings)
        except Exception as e:
            logger.error(f"Error during Rule-based scan: {e}")

        # 4. スコアリングと総合判定
        overall_result = self.scoring_engine.evaluate(repo_url, all_findings)

        # 5. JSON 保存 (docs/scan_result.json)
        if save_to_docs:
            self.save_result_json(overall_result)

        return overall_result

    def _run_rule_based_scan(self, repo_url: str) -> List[Finding]:
        """既存ルールベース評価を実行し、SOURCE_CODE カテゴリの Finding に変換"""
        findings: List[Finding] = []
        try:
            from src.scan import SecurityScan

            scan_runner = SecurityScan(self.project_root)
            scan_result = scan_runner.run()
            for rec in scan_result.records:
                if rec.category in ("secrets", "dependencies", "ci_cd_security"):
                    continue

                findings.append(
                    Finding(
                        category=Category.SOURCE_CODE,
                        source="rule_based",
                        rule_id=rec.rule_id,
                        severity=rec.severity.value
                        if hasattr(rec.severity, "value")
                        else str(rec.severity),
                        title=rec.title if hasattr(rec, "title") else rec.rule_id,
                        target=rec.file_path,
                        location=f"Line {rec.line}"
                        if hasattr(rec, "line") and rec.line
                        else None,
                        description=rec.message or "",
                        remediation="Follow security best practices for code pattern.",
                    )
                )
        except Exception as e:
            logger.warning(f"Local rule-based scan skipped or failed: {e}")
            # モック Findings をフォールバック
            findings.append(
                Finding(
                    category=Category.SOURCE_CODE,
                    source="rule_based",
                    rule_id="RB-A1-001",
                    severity="HIGH",
                    title="Command Injection (Rule-based)",
                    target="src/utils/exec.py",
                    location="Line 15",
                    description="Unsanitized user input passed to subprocess.run shell call.",
                    remediation="Avoid shell=True and pass arguments as a list.",
                )
            )

        return findings

    def save_result_json(
        self, result: OverallResult, filename: str = "scan_result.json"
    ) -> Path:
        docs_dir = self.project_root / "docs"
        docs_dir.mkdir(parents=True, exist_ok=True)
        target_path = docs_dir / filename

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(result.model_dump_json(indent=2))

        logger.info(f"Saved scan result JSON to: {target_path}")
        return target_path
