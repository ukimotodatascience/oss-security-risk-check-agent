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
        rule_scan_executed = False
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

                def _is_in_subdir(item: Any, subdir: str) -> bool:
                    p = (item.path if hasattr(item, "path") else str(item)).replace(
                        "\\", "/"
                    )
                    parts = [part for part in p.split("/") if part]
                    if not parts:
                        return False
                    norm_subdir = subdir.replace("\\", "/").strip("/")
                    if not norm_subdir:
                        return True
                    sub_lower = norm_subdir.lower()

                    # Archive zip paths start with top-level directory (e.g. repo-ref/services/api/file.ext)
                    # Candidate 1: relative path after stripping top-level archive directory
                    rel_path = "/".join(parts[1:]) if len(parts) > 1 else ""
                    if rel_path:
                        rel_lower = rel_path.lower()
                        if rel_lower == sub_lower or rel_lower.startswith(
                            sub_lower + "/"
                        ):
                            return True

                    # Candidate 2: raw path itself (if path was already relative)
                    raw_lower = "/".join(parts).lower()
                    if raw_lower == sub_lower or raw_lower.startswith(sub_lower + "/"):
                        return True

                    return False

                relevant_skipped_files = (
                    [
                        f
                        for f in fetcher.skipped_files
                        if _is_in_subdir(f, target_subdir)
                    ]
                    if target_subdir
                    else fetcher.skipped_files
                )

                if relevant_skipped_files:
                    logger.warning(
                        f"ArchiveSnapshotFetcher skipped {len(relevant_skipped_files)} files in target scope due to size limits."
                    )
                    for cat in (
                        Category.MISCONFIGURATION,
                        Category.KNOWN_VULNERABILITIES,
                        Category.SECRETS,
                        Category.SOURCE_CODE,
                    ):
                        all_findings.append(
                            Finding(
                                category=cat,
                                source="snapshot_fetcher",
                                rule_id="SKIPPED-FILES-LIMIT",
                                severity="LOW",
                                title="Large Files Skipped During Fetch",
                                description=f"{len(relevant_skipped_files)} file(s) in target scope were skipped due to size limits during snapshot fetch.",
                                remediation="Review large files individually for secrets or vulnerabilities.",
                            )
                        )

                # Record Git History unevaluated alert for snapshot scan
                if not (extracted_dir / ".git").exists():
                    for cat in (Category.SECRETS, Category.MAINTENANCE):
                        all_findings.append(
                            Finding(
                                category=cat,
                                source="snapshot_fetcher",
                                rule_id="GIT-HISTORY-UNEVALUATED",
                                severity="INFO",
                                title="Git History Check Skipped (Snapshot Only)",
                                description="Scan performed on archive snapshot without .git directory. Commit history and deleted secrets were not evaluated.",
                                remediation="Run scan on full git repository clone for commit history evaluation.",
                            )
                        )
                    scanner_status["git_history"] = False

                trivy_findings, success = self.trivy_adapter.run_scan_with_status(
                    str(extracted_dir),
                    target_ref=target_ref,
                    target_subdir=target_subdir,
                )
                all_findings.extend(trivy_findings)
                if success and not relevant_skipped_files:
                    scanner_status["trivy"] = True

                # 4. 既存 Rule-based Scan (スナップショット生存中に判定)
                try:
                    rule_scan_executed = True
                    rule_findings, success = self._run_rule_based_scan(
                        normalized_url,
                        scanner_status=scanner_status,
                        target_dir=extracted_dir,
                    )
                    all_findings.extend(rule_findings)
                    if success and not relevant_skipped_files:
                        scanner_status["rule_based"] = True
                except Exception as e:
                    logger.error(f"Error during Rule-based scan: {e}")

        except Exception as e:
            logger.warning(
                f"Safe snapshot fetch failed or refused for Trivy scan ({e}). Skipping Trivy scan to prevent resource exhaustion."
            )

        # 3. OpenSSF Scorecard Scan (Supply Chain, Dev Process, CI/CD, Maintenance)
        if not target_ref and not target_subdir:
            try:
                scorecard_findings = self.scorecard_adapter.run_scan(normalized_url)
                all_findings.extend(scorecard_findings)
                if scorecard_findings:
                    scanner_status["scorecard"] = True
            except Exception as e:
                logger.error(f"Error during Scorecard scan: {e}")
        else:
            logger.info(
                "Skipping Scorecard scan because target_ref or target_subdir is set (Scorecard evaluates default branch/entire repo only)."
            )
            scanner_status["scorecard"] = False

        # スナップショット取得が失敗した場合（一度もルールスキャンが実行されていない場合）の Rule-based Scan フォールバック
        if not rule_scan_executed:
            try:
                rule_findings, success = self._run_rule_based_scan(
                    normalized_url,
                    scanner_status=scanner_status,
                )
                all_findings.extend(rule_findings)
                if success:
                    scanner_status["rule_based"] = True
            except Exception as e:
                logger.error(f"Error during Rule-based fallback scan: {e}")

        # Trivy 成功時は Trivy と重複する CVE/GHSA の B-1 ルール Finding のみを除外して二重減点を防止
        if scanner_status.get("trivy"):
            import re

            trivy_vuln_ids: set[str] = set()
            for f in all_findings:
                if f.source == "trivy":
                    text = f"{f.rule_id} {f.title} {f.description or ''}"
                    cves = set(re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE))
                    ghsas = set(
                        re.findall(
                            r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                            text,
                            re.IGNORECASE,
                        )
                    )
                    trivy_vuln_ids.update(v.upper() for v in (cves | ghsas))

            filtered_findings: List[Finding] = []
            for f in all_findings:
                is_b1 = (
                    f.source == "rule_based"
                    and f.category == Category.KNOWN_VULNERABILITIES
                    and (f.rule_id == "B-1" or str(f.rule_id).startswith("B-1"))
                )
                if is_b1:
                    text = f"{f.rule_id} {f.title} {f.description or ''}"
                    b1_cves = set(re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE))
                    b1_ghsas = set(
                        re.findall(
                            r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                            text,
                            re.IGNORECASE,
                        )
                    )
                    b1_ids = {v.upper() for v in (b1_cves | b1_ghsas)}
                    if b1_ids and b1_ids.issubset(trivy_vuln_ids):
                        continue
                filtered_findings.append(f)
            all_findings = filtered_findings

        # 重複する Finding の排除
        seen_keys = set()
        deduped_findings: List[Finding] = []
        for f in all_findings:
            key = (
                f.category,
                f.rule_id,
                f.target or "",
                f.location or "",
                f.title,
                f.description or "",
            )
            if key not in seen_keys:
                seen_keys.add(key)
                deduped_findings.append(f)
        all_findings = deduped_findings

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

    def _run_rule_based_scan(
        self,
        repo_url: str,
        scanner_status: Optional[Dict[str, bool]] = None,
        target_dir: Optional[Path] = None,
    ) -> tuple[List[Finding], bool]:
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

            if target_dir and target_dir.exists():
                from src.config import ScanConfig
                from src.rule_engine import load_all_rules, run_all
                from src.rules.B_dependencies.vuln_sources import VulnLookupService

                config = ScanConfig(self.project_root, self.cli_options)
                rules = load_all_rules(self.project_root)
                with VulnLookupService.use_config(
                    cache_dir=config.resolve_vuln_cache_dir(),
                    cache_ttl=config.resolve_vuln_cache_ttl(),
                ):
                    records, errors, _ = run_all(target_dir, rules)
                has_errors = bool(errors)
            else:
                effective_opts = CliOptions(
                    target_url=repo_url,
                    target_ref=target_ref,
                    target_subdir=target_subdir,
                    output_dir=output_dir,
                    mvp=False,
                )
                scan_runner = SecurityScan(
                    self.project_root, cli_options=effective_opts, persist_report=False
                )
                scan_result = scan_runner.run()
                records = scan_result.records
                errors = getattr(scan_result, "errors", []) or []
                has_errors = bool(errors)

            if len(records) == 0 and has_errors:
                logger.warning("Rule-based scan returned 0 records with errors.")
                return [], False

            # Finding 数上限チェック (500件上限)
            max_limit = 500
            has_global_limit = (
                any(err[0] == "GLOBAL_LIMIT" for err in errors) if errors else False
            )
            truncated = False
            if len(records) > max_limit or has_global_limit:
                records = records[:max_limit]
                has_errors = True
                truncated = True

            RULE_CAT_TO_MVP_CAT: Dict[str, Category] = {
                "secrets": Category.SECRETS,
                "dependencies": Category.DEPENDENCIES,
                "cicd": Category.CICD,
                "known_vulnerabilities": Category.KNOWN_VULNERABILITIES,
                "misconfiguration": Category.MISCONFIGURATION,
                "config": Category.MISCONFIGURATION,
                "maintenance": Category.MAINTENANCE,
                "license": Category.DEVELOPMENT,
                "code": Category.SOURCE_CODE,
                "source_code": Category.SOURCE_CODE,
            }

            for rec in records:
                raw_cat_str = (
                    str(rec.category).lower() if hasattr(rec, "category") else ""
                )
                rule_id_str = str(rec.rule_id) if hasattr(rec, "rule_id") else ""
                if rule_id_str == "B-1" or rule_id_str.startswith("B-1"):
                    mvp_cat = Category.KNOWN_VULNERABILITIES
                else:
                    mvp_cat = RULE_CAT_TO_MVP_CAT.get(raw_cat_str, Category.SOURCE_CODE)

                findings.append(
                    Finding(
                        category=mvp_cat,
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

            if truncated:
                affected_categories = {f.category for f in findings}
                if not affected_categories:
                    affected_categories = {Category.SOURCE_CODE}
                for cat in affected_categories:
                    findings.append(
                        Finding(
                            category=cat,
                            source="rule_based",
                            rule_id="FINDINGS-LIMIT-EXCEEDED",
                            severity="LOW",
                            title="Rule Findings Limit Exceeded",
                            description=f"Rule scan generated over {max_limit} findings. Truncated excess findings.",
                            remediation="Review findings or narrow scan scope.",
                        )
                    )

            return findings, not has_errors
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
