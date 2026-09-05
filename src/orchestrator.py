from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, List, Optional

from src.adapters.scorecard_adapter import ScorecardAdapter
from src.adapters.trivy_adapter import TrivyAdapter
from src.mvp_models import Category, Finding, OverallResult
from src.scoring.engine import ScoringEngine
from src.targets.url_validator import parse_github_repo_url

logger = logging.getLogger(__name__)


class MVPOrchestrator:
    def __init__(
        self, project_root: Optional[Path] = None, cli_options: Optional[Any] = None
    ) -> None:
        self.project_root = project_root or Path(__file__).resolve().parent.parent
        self.cli_options = cli_options
        self.trivy_adapter = TrivyAdapter()
        self.scorecard_adapter = ScorecardAdapter()
        self.scoring_engine = ScoringEngine()

    def run_full_scan(
        self,
        repo_url: str,
        save_to_docs: bool = True,
        output_dir: Optional[Path] = None,
    ) -> OverallResult:
        # 1. URL の検証と正規化 (TOKENの露出や無効URLの防止)
        try:
            ref = parse_github_repo_url(repo_url)
            normalized_url = f"https://github.com/{ref.owner}/{ref.repo}"
        except Exception as e:
            logger.error(f"Invalid target URL: {e}")
            raise ValueError(f"Invalid target URL for scan: {e}") from e

        logger.info(f"Starting MVP full scan for repository: {normalized_url}")
        all_findings: List[Finding] = []

        # 2. Trivy Scan (既知脆弱性, Secret, 設定)
        try:
            trivy_findings = self.trivy_adapter.run_scan(normalized_url)
            all_findings.extend(trivy_findings)
        except Exception as e:
            logger.error(f"Error during Trivy scan: {e}")

        # 3. OpenSSF Scorecard Scan (Supply Chain, Dev Process, CI/CD, Maintenance)
        try:
            scorecard_findings = self.scorecard_adapter.run_scan(normalized_url)
            all_findings.extend(scorecard_findings)
        except Exception as e:
            logger.error(f"Error during Scorecard scan: {e}")

        # 4. 既存 Rule-based Scan (ソースコード固有の判定)
        try:
            rule_findings = self._run_rule_based_scan(normalized_url)
            all_findings.extend(rule_findings)
        except Exception as e:
            logger.error(f"Error during Rule-based scan: {e}")

        # 5. スコアリングと総合判定
        overall_result = self.scoring_engine.evaluate(normalized_url, all_findings)

        # 6. JSON 保存
        if save_to_docs:
            self.save_result_json(overall_result, output_dir=output_dir)

        return overall_result

    def _run_rule_based_scan(self, repo_url: str) -> List[Finding]:
        """既存ルールベース評価を実行し、SOURCE_CODE カテゴリの Finding に変換"""
        findings: List[Finding] = []
        try:
            from src.scan import SecurityScan

            # SecurityScan へ CLI オプションを明示的に伝播
            scan_runner = SecurityScan(self.project_root, cli_options=self.cli_options)
            scan_result = scan_runner.run()
            for rec in scan_result.records:
                # 既存カテゴリ名 'cicd', 'secrets', 'dependencies' と正しく比較して除外
                if rec.category in ("secrets", "dependencies", "cicd"):
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

        return findings

    def save_result_json(
        self,
        result: OverallResult,
        filename: str = "scan_result.json",
        output_dir: Optional[Path] = None,
    ) -> Path:
        target_dir = output_dir or (self.project_root / "docs")
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / filename

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(result.model_dump_json(indent=2))

        logger.info(f"Saved scan result JSON to: {target_path}")
        return target_path
