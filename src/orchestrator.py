from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

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
        scanner_status: Dict[str, bool] = {
            "trivy": False,
            "scorecard": False,
            "rule_based": False,
        }

        # 2. Trivy Scan (既知脆弱性, Secret, 設定)
        # ArchiveSnapshotFetcher を使用して安全上限 (ダウンロード・解凍サイズ、ファイル数) を適用
        try:
            from src.config import ScanConfig
            from src.targets.archive_fetcher import ArchiveSnapshotFetcher
            from src.targets.models import ScanTargetSpec
            import tempfile

            config = ScanConfig(self.project_root, self.cli_options)
            limits = config.resolve_remote_fetch_limits()
            fetcher = ArchiveSnapshotFetcher(
                max_download_bytes=limits.max_download_bytes,
                max_extracted_bytes=limits.max_extracted_bytes,
                max_files=limits.max_files,
                max_single_file_bytes=limits.max_single_file_bytes,
                timeout_sec=limits.timeout_sec,
                github_token=config.resolve_github_token(),
            )

            target_ref = (
                getattr(self.cli_options, "target_ref", None)
                if self.cli_options
                else None
            )
            target_subdir = (
                getattr(self.cli_options, "target_subdir", None)
                if self.cli_options
                else None
            )

            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                spec = ScanTargetSpec(
                    source_type="remote_archive",
                    repo_url=normalized_url,
                    ref=target_ref,
                    subdir=target_subdir,
                )
                extracted_dir = fetcher.fetch(spec, tmp_path)
                logger.info(
                    f"Fetched snapshot safely for Trivy scan at: {extracted_dir}"
                )

                if fetcher.skipped_files:
                    logger.warning(
                        f"ArchiveSnapshotFetcher skipped {len(fetcher.skipped_files)} files due to size limits."
                    )
                    all_findings.append(
                        Finding(
                            category=Category.MISCONFIGURATION,
                            source="snapshot_fetcher",
                            rule_id="SKIPPED-FILES-LIMIT",
                            severity="LOW",
                            title="Large Files Skipped During Fetch",
                            description=f"{len(fetcher.skipped_files)} file(s) were skipped due to size limits during snapshot fetch.",
                            remediation="Review large files individually for secrets or vulnerabilities.",
                        )
                    )

                trivy_findings, success = self.trivy_adapter.run_scan_with_status(
                    str(extracted_dir)
                )
                all_findings.extend(trivy_findings)
                if success:
                    scanner_status["trivy"] = True
        except Exception as e:
            logger.warning(
                f"Safe snapshot fetch failed or refused for Trivy scan ({e}). Skipping Trivy scan to prevent resource exhaustion."
            )

        # 3. OpenSSF Scorecard Scan (Supply Chain, Dev Process, CI/CD, Maintenance)
        try:
            scorecard_findings = self.scorecard_adapter.run_scan(normalized_url)
            all_findings.extend(scorecard_findings)
            if scorecard_findings:
                scanner_status["scorecard"] = True
        except Exception as e:
            logger.error(f"Error during Scorecard scan: {e}")

        # 4. 既存 Rule-based Scan (ソースコード固有の判定)
        try:
            rule_findings, success = self._run_rule_based_scan(normalized_url)
            all_findings.extend(rule_findings)
            if success:
                scanner_status["rule_based"] = True
        except Exception as e:
            logger.error(f"Error during Rule-based scan: {e}")

        # 5. スコアリングと総合判定
        overall_result = self.scoring_engine.evaluate(
            normalized_url,
            all_findings,
            scanner_status=scanner_status,
            scanned_ref=target_ref,
            scanned_subdir=target_subdir,
        )

        # 6. JSON 保存
        if save_to_docs:
            self.save_result_json(overall_result, output_dir=output_dir)

        return overall_result

    def _run_rule_based_scan(self, repo_url: str) -> tuple[List[Finding], bool]:
        """既存ルールベース評価を実行し (findings, success_flag) を返す"""
        findings: List[Finding] = []
        try:
            from main import CliOptions
            from src.scan import SecurityScan

            target_ref = (
                getattr(self.cli_options, "target_ref", None)
                if self.cli_options
                else None
            )
            target_subdir = (
                getattr(self.cli_options, "target_subdir", None)
                if self.cli_options
                else None
            )
            output_dir = (
                getattr(self.cli_options, "output_dir", None)
                if self.cli_options
                else None
            )

            effective_opts = CliOptions(
                target_url=repo_url,
                target_ref=target_ref,
                target_subdir=target_subdir,
                output_dir=output_dir,
                mvp=False,
            )

            scan_runner = SecurityScan(self.project_root, cli_options=effective_opts)
            scan_result = scan_runner.run()
            for rec in scan_result.records:
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
            return findings, True
        except Exception as e:
            logger.warning(f"Local rule-based scan skipped or failed: {e}")

        return findings, False

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
