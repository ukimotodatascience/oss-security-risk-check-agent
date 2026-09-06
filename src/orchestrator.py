from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.scorecard_adapter import ScorecardAdapter
from src.adapters.trivy_adapter import TrivyAdapter
from src.mvp_models import Category, Finding, OverallResult
from src.scoring.engine import ScoringEngine
from src.targets.archive_fetcher import ArchiveSnapshotFetcher
from src.targets.url_validator import parse_github_repo_url

logger = logging.getLogger(__name__)


def _normalize_subdir(subdir: Optional[str]) -> Optional[str]:
    if not subdir:
        return None

    raw_clean = subdir.replace("\\", "/").strip()
    if not raw_clean or raw_clean == ".":
        return None

    is_absolute = raw_clean.startswith("/") or (
        len(raw_clean) > 1 and raw_clean[1] == ":"
    )

    parts = [pt for pt in raw_clean.split("/") if pt and pt != "."]
    norm_parts: list[str] = []
    is_out_of_bounds = is_absolute

    for pt in parts:
        if pt == "..":
            if norm_parts:
                norm_parts.pop()
            else:
                is_out_of_bounds = True
        else:
            norm_parts.append(pt)

    if is_out_of_bounds:
        return subdir

    res = "/".join(norm_parts)
    return res if res else None


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
        target_ref = (
            getattr(self.cli_options, "target_ref", None) if self.cli_options else None
        )
        target_subdir = (
            getattr(self.cli_options, "target_subdir", None)
            if self.cli_options
            else None
        )
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

                def _normalize_rel_path(p_str: str) -> str:
                    parts = [
                        pt
                        for pt in p_str.replace("\\", "/").split("/")
                        if pt and pt != "."
                    ]
                    norm_parts: list[str] = []
                    for pt in parts:
                        if pt == "..":
                            if norm_parts:
                                norm_parts.pop()
                        else:
                            norm_parts.append(pt)
                    return "/".join(norm_parts)

                def _is_in_subdir(item: Any, subdir: str) -> bool:
                    raw_path = item.path if hasattr(item, "path") else str(item)
                    norm_item = _normalize_rel_path(raw_path)
                    norm_sub = _normalize_rel_path(subdir)

                    if not norm_sub:
                        return True

                    item_parts = [p for p in norm_item.split("/") if p]
                    if not item_parts:
                        return False

                    # Candidate 1: relative path after stripping top-level archive directory
                    rel_path = "/".join(item_parts[1:]) if len(item_parts) > 1 else ""
                    if rel_path:
                        if rel_path == norm_sub or rel_path.startswith(norm_sub + "/"):
                            return True

                    # Candidate 2: raw path itself (if path was already relative)
                    raw_path_str = "/".join(item_parts)
                    if raw_path_str == norm_sub or raw_path_str.startswith(
                        norm_sub + "/"
                    ):
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
                        f"Snapshot fetcher skipped {len(relevant_skipped_files)} files in target scope."
                    )
                    scanner_status["has_skipped_files"] = True
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
                                severity="INFO",
                                title="Files Skipped Due to Limits",
                                description=f"Snapshot fetcher skipped {len(relevant_skipped_files)} files due to size limits.",
                                remediation="Review skipped files or increase fetch limits.",
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
        is_default_branch_ref = not target_ref or target_ref.strip().upper() == "HEAD"
        norm_subdir = _normalize_subdir(target_subdir)
        if is_default_branch_ref and not norm_subdir:
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

        # Trivy 検出時は Trivy と重複する CVE/GHSA の B-1 ルール Finding を除外して二重減点を防止
        if any(f.source == "trivy" for f in all_findings):
            import re

            trivy_vulns: set[tuple[str, str]] = set()
            trivy_vuln_ids_global: set[str] = set()
            for f in all_findings:
                if f.source == "trivy":
                    text = f"{f.rule_id} {f.title}"
                    cves = set(re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE))
                    ghsas = set(
                        re.findall(
                            r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                            text,
                            re.IGNORECASE,
                        )
                    )
                    tf_pkg = ""
                    if f.location:
                        if "@" in f.location:
                            tf_pkg = f.location.rsplit("@", 1)[0].strip().lower()
                        else:
                            tf_pkg = f.location.strip().lower()
                    if not tf_pkg and f.description:
                        pm = re.search(
                            r"Package:\s*([^\s\n]+)", f.description, re.IGNORECASE
                        )
                        if pm:
                            tf_pkg = pm.group(1).strip().lower()

                    for v in cves | ghsas:
                        v_upper = v.upper()
                        trivy_vulns.add((v_upper, tf_pkg))
                        trivy_vuln_ids_global.add(v_upper)

            filtered_findings: List[Finding] = []
            for f in all_findings:
                is_b1 = (
                    f.source == "rule_based"
                    and f.category == Category.KNOWN_VULNERABILITIES
                    and (f.rule_id == "B-1" or str(f.rule_id).startswith("B-1"))
                )
                if is_b1:
                    text = f"{f.title} {f.description or ''}"
                    b1_pkg = ""
                    if f.description:
                        m_pkg = re.match(r"^([^\s\[:]+)", f.description.strip())
                        if m_pkg:
                            b1_pkg = m_pkg.group(1).strip().lower()

                    main_m = re.search(r"\[[^\]]+:([A-Za-z0-9_-]+)\]", text)
                    if main_m:
                        b1_ids = {main_m.group(1).upper()}
                    else:
                        b1_cves = set(re.findall(r"CVE-\d{4}-\d+", text, re.IGNORECASE))
                        b1_ghsas = set(
                            re.findall(
                                r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",
                                text,
                                re.IGNORECASE,
                            )
                        )
                        b1_ids = {v.upper() for v in (b1_cves | b1_ghsas)}

                    is_dup = False
                    for vid in b1_ids:
                        if b1_pkg and (vid, b1_pkg) in trivy_vulns:
                            is_dup = True
                            break
                        elif (vid, "") in trivy_vulns:
                            is_dup = True
                            break
                        elif not b1_pkg and vid in trivy_vuln_ids_global:
                            is_dup = True
                            break
                    if is_dup:
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
        has_skipped_files = False
        try:
            from main import CliOptions
            from src.rule_engine import load_all_rules, run_all
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

            executed_count = 0
            if target_dir and target_dir.exists():
                file_count = sum(1 for p in target_dir.rglob("*") if p.is_file())
                has_skipped_in_status = bool(
                    scanner_status and scanner_status.get("has_skipped_files")
                )
                if file_count == 0 and (has_skipped_files or has_skipped_in_status):
                    logger.warning(
                        "Target directory contains 0 files and all files were skipped due to size limits."
                    )
                    if scanner_status is not None:
                        scanner_status["rule_based"] = False
                        for cat in (
                            Category.MISCONFIGURATION,
                            Category.KNOWN_VULNERABILITIES,
                            Category.SECRETS,
                            Category.SOURCE_CODE,
                        ):
                            cat_key = (
                                cat.value if hasattr(cat, "value") else str(cat).lower()
                            )
                            scanner_status[f"rule_based_{cat_key}"] = False
                    findings.append(
                        Finding(
                            category=Category.SOURCE_CODE,
                            source="rule_based",
                            rule_id="ALL-FILES-SKIPPED-LIMIT",
                            severity="INFO",
                            title="Target Directory Empty (All Files Skipped)",
                            description="Target directory contains no files to scan because all files were skipped due to size limits.",
                            remediation="Check target path or increase fetch limits.",
                        )
                    )
                    return findings, False

                from src.config import ScanConfig
                from src.rules.B_dependencies.vuln_sources import VulnLookupService

                config = ScanConfig(self.project_root, self.cli_options)
                rules = load_all_rules(self.project_root)

                with VulnLookupService.use_config(
                    cache_dir=config.resolve_vuln_cache_dir(),
                    cache_ttl=config.resolve_vuln_cache_ttl(),
                ):
                    records, errors, executed_count = run_all(target_dir, rules)
                has_errors = bool(errors)

                if not rules:
                    logger.warning("No security rules loaded from rule engine.")
                    if scanner_status is not None:
                        scanner_status["rule_based"] = False
                    findings.append(
                        Finding(
                            category=Category.SOURCE_CODE,
                            source="rule_based",
                            rule_id="NO-RULES-LOADED",
                            severity="INFO",
                            title="No Security Rules Loaded",
                            description="Rule engine found 0 rules to execute.",
                            remediation="Ensure security rules are properly configured in project root.",
                        )
                    )
                    if not records and not errors:
                        return findings, False
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
                try:
                    scan_result = scan_runner.run()
                    records = scan_result.records
                    errors = getattr(scan_result, "errors", []) or []
                    executed_count = getattr(
                        scan_result,
                        "executed_rule_count",
                        getattr(scan_result, "loaded_rule_count", 0),
                    )
                    has_errors = bool(errors)
                except SystemExit as e:
                    logger.warning(f"Fallback SecurityScan.run() exited: {e}")
                    scan_result = None
                    records = []
                    errors = [
                        (
                            "NO-RULES-LOADED",
                            "Rule engine found 0 rules to execute.",
                        )
                    ]
                    executed_count = 0
                    has_errors = True
                except Exception as e:
                    logger.warning(f"Fallback SecurityScan.run() failed: {e}")
                    scan_result = None
                    records = []
                    exc_type_name = type(e).__name__
                    errors = [
                        (
                            "FALLBACK-SCAN-FAILED",
                            f"Fallback scan failed: {exc_type_name}: {e}",
                        )
                    ]
                    executed_count = 0
                    has_errors = True

                # 履歴・省略ファイルの情報を伝播
                target_obj = getattr(scan_result, "target", None)
                is_zipball = (
                    target_obj
                    and getattr(target_obj, "fetch_mode", "")
                    == "github_archive_zipball"
                )
                no_git = (
                    target_obj
                    and hasattr(target_obj, "local_dir")
                    and target_obj.local_dir
                    and not (target_obj.local_dir / ".git").exists()
                )
                if (is_zipball or no_git) and scanner_status is not None:
                    scanner_status["git_history"] = False
                    for cat in (Category.SECRETS, Category.MAINTENANCE):
                        findings.append(
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

                skipped = getattr(scan_result, "skipped_files", None)
                if skipped and not isinstance(skipped, (str, bytes)):
                    try:
                        skipped_list = list(skipped)
                    except Exception:
                        skipped_list = []
                    if skipped_list:
                        relevant_skipped = (
                            [
                                f
                                for f in skipped_list
                                if ArchiveSnapshotFetcher._is_in_subdir(
                                    f, target_subdir
                                )
                            ]
                            if target_subdir
                            else skipped_list
                        )
                        if relevant_skipped:
                            target_obj = getattr(scan_result, "target", None)
                            scan_path = (
                                getattr(target_obj, "scan_path", None)
                                if target_obj
                                else None
                            )
                            file_count = getattr(
                                scan_result, "scanned_file_count", None
                            )
                            if not isinstance(file_count, int) or isinstance(
                                file_count, bool
                            ):
                                file_count = None

                            if file_count is None and scan_path is not None:
                                if scan_path.exists():
                                    file_count = sum(
                                        1 for p in scan_path.rglob("*") if p.is_file()
                                    )
                                else:
                                    file_count = 0

                            has_skipped_files = True
                            if scanner_status is not None:
                                scanner_status["rule_based"] = False
                                for cat in (
                                    Category.MISCONFIGURATION,
                                    Category.KNOWN_VULNERABILITIES,
                                    Category.SECRETS,
                                    Category.SOURCE_CODE,
                                ):
                                    cat_key = (
                                        cat.value
                                        if hasattr(cat, "value")
                                        else str(cat).lower()
                                    )
                                    scanner_status[f"rule_based_{cat_key}"] = False

                            if file_count == 0:
                                logger.warning(
                                    "Fallback scan path contains 0 files and all files were skipped due to size limits. Clearing rule records."
                                )
                                records = []

                            for cat in (
                                Category.MISCONFIGURATION,
                                Category.KNOWN_VULNERABILITIES,
                                Category.SECRETS,
                                Category.SOURCE_CODE,
                            ):
                                findings.append(
                                    Finding(
                                        category=cat,
                                        source="snapshot_fetcher",
                                        rule_id="SKIPPED-FILES-LIMIT",
                                        severity="INFO",
                                        title="Files Skipped Due to Limits",
                                        description=f"Snapshot fetcher skipped {len(relevant_skipped)} files due to size limits.",
                                        remediation="Review skipped files or increase fetch limits.",
                                    )
                                )

                            if file_count == 0:
                                return findings, False

            if len(records) == 0 and has_errors:
                logger.warning("Rule-based scan returned 0 records with errors.")

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
                "runtime": Category.SOURCE_CODE,
                "crypto": Category.SOURCE_CODE,
                "logging": Category.SOURCE_CODE,
                "auth": Category.SOURCE_CODE,
                "malware": Category.SOURCE_CODE,
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
                            severity="INFO",
                            title="Rule Findings Limit Exceeded",
                            description=f"Rule scan generated over {max_limit} findings. Truncated excess findings.",
                            remediation="Review findings or narrow scan scope.",
                        )
                    )
            if errors:
                rule_by_id = (
                    {str(getattr(r, "rule_id", getattr(r, "id", ""))): r for r in rules}
                    if "rules" in locals() and rules
                    else {}
                )
                errored_categories: set[Category] = set()
                for err_entry in errors:
                    err_rule_id = err_entry[0]
                    err_detail = err_entry[1]
                    exc_type = getattr(err_entry, "exc_type", None) or (
                        err_entry[2] if len(err_entry) > 2 and err_entry[2] else None
                    )
                    if not exc_type and err_detail:
                        m = re.search(
                            r"^(?:[a-zA-Z_][a-zA-Z0-9_]*\.)*([A-Z][A-Za-z0-9_]*(?:Error|Exception|Fault|Warning)?):",
                            str(err_detail),
                            re.MULTILINE,
                        )
                        if m:
                            exc_type = m.group(1)
                    if not exc_type:
                        exc_type = "Rule execution error"

                    if err_rule_id == "NO-RULES-LOADED":
                        if scanner_status is not None:
                            scanner_status["rule_based"] = False
                        findings.append(
                            Finding(
                                category=Category.SOURCE_CODE,
                                source="rule_based",
                                rule_id="NO-RULES-LOADED",
                                severity="INFO",
                                title="No Security Rules Loaded",
                                description="Rule engine found 0 rules to execute.",
                                remediation="Ensure security rules are properly configured in project root.",
                            )
                        )
                        continue

                    if err_rule_id == "GLOBAL_LIMIT":
                        if scanner_status is not None:
                            scanner_status["rule_based"] = False
                        findings.append(
                            Finding(
                                category=Category.SOURCE_CODE,
                                source="rule_based",
                                rule_id="GLOBAL-LIMIT-EXCEEDED",
                                severity="INFO",
                                title="Rule Scan Global Limit Exceeded",
                                description="Rule engine hit global limit of 500 records. Scan was truncated and remaining rules were skipped.",
                                remediation="Review findings or narrow scan scope.",
                            )
                        )
                        continue

                    if err_rule_id == "FALLBACK-SCAN-FAILED":
                        if scanner_status is not None:
                            scanner_status["rule_based"] = False
                        findings.append(
                            Finding(
                                category=Category.SOURCE_CODE,
                                source="rule_based",
                                rule_id="FALLBACK-SCAN-FAILED-UNEVALUATED",
                                severity="INFO",
                                title="Fallback Scan Execution Failed",
                                description=str(err_detail),
                                remediation="Review target reference, network connection, or permissions.",
                            )
                        )
                        continue

                    err_rule_str = str(err_rule_id)
                    if err_rule_str in rule_by_id:
                        raw_cat_str = str(rule_by_id[err_rule_str].category).lower()
                    else:
                        raw_cat_str = ""

                    if err_rule_str == "B-1" or err_rule_str.startswith("B-1"):
                        err_cat = Category.KNOWN_VULNERABILITIES
                    elif raw_cat_str in RULE_CAT_TO_MVP_CAT:
                        err_cat = RULE_CAT_TO_MVP_CAT[raw_cat_str]
                    else:
                        prefix = err_rule_str[0].upper() if err_rule_str else ""
                        prefix_to_cat = {
                            "A": Category.SOURCE_CODE,
                            "B": Category.DEPENDENCIES,
                            "C": Category.CICD,
                            "D": Category.MISCONFIGURATION,
                            "E": Category.SOURCE_CODE,
                            "F": Category.SECRETS,
                            "G": Category.SOURCE_CODE,
                            "H": Category.SOURCE_CODE,
                            "I": Category.SOURCE_CODE,
                            "J": Category.MAINTENANCE,
                            "K": Category.DEVELOPMENT,
                            "L": Category.SOURCE_CODE,
                        }
                        err_cat = prefix_to_cat.get(prefix, Category.SOURCE_CODE)

                    errored_categories.add(err_cat)

                    findings.append(
                        Finding(
                            category=err_cat,
                            source="rule_based",
                            rule_id=f"{err_rule_id}-UNEVALUATED",
                            severity="INFO",
                            title=f"Rule {err_rule_id} Execution Unevaluated",
                            description=f"Rule {err_rule_id} failed during execution: {exc_type}",
                            remediation="Review rule execution settings, timeouts, or system resources.",
                        )
                    )

                if scanner_status is not None:
                    for ec in errored_categories:
                        cat_key = ec.value if hasattr(ec, "value") else str(ec).lower()
                        scanner_status[f"rule_based_{cat_key}"] = False

            non_global_errors = [e for e in errors if e[0] != "GLOBAL_LIMIT"]
            if not isinstance(executed_count, int) or isinstance(executed_count, bool):
                executed_count = max(1, len(records) + len(errors))

            all_rules_failed = (
                executed_count == 0 or len(non_global_errors) >= executed_count
            ) and len(records) == 0

            scan_success = not (
                all_rules_failed or has_global_limit or has_skipped_files
            )
            return findings, scan_success
        except Exception as e:
            logger.warning(f"Local rule-based scan skipped or failed: {e}")

        return findings, False

    def save_result_json(
        self,
        result: OverallResult,
        filename: str = "scan_result.json",
        output_dir: Optional[Path] = None,
    ) -> Path:
        import copy

        target_dir = output_dir or (self.project_root / "docs")
        target_dir.mkdir(parents=True, exist_ok=True)
        target_path = target_dir / filename

        # Create isolated deep copy to prevent mutating the original caller's OverallResult object
        result_to_save = copy.deepcopy(result)

        json_str = result_to_save.model_dump_json(indent=2)
        MAX_FILE_BYTES = 10 * 1024 * 1024  # 10MB UI limit in docs/app.js

        def _truncate_finding(f: Finding, max_len: int = 200) -> None:
            for attr in (
                "description",
                "title",
                "target",
                "remediation",
                "location",
                "rule_id",
                "source",
            ):
                val = getattr(f, attr, None)
                if isinstance(val, str) and len(val) > max_len:
                    setattr(f, attr, val[:max_len] + "...")

        def _truncate_top_level_strings(res: OverallResult, max_len: int = 200) -> None:
            for attr in (
                "repository_url",
                "scanned_ref",
                "scanned_subdir",
                "status_reason",
            ):
                val = getattr(res, attr, None)
                if isinstance(val, str) and len(val) > max_len:
                    setattr(res, attr, val[:max_len] + "...")

        def _sync_findings_counts(res: OverallResult) -> None:
            for cat_res in res.categories.values():
                cat_res.findings_count = len(cat_res.findings)

        if len(json_str.encode("utf-8")) > MAX_FILE_BYTES:
            logger.warning(
                "Scan result JSON exceeded 10MB limit. Truncating text fields to fit."
            )
            _truncate_top_level_strings(result_to_save, 200)
            # Pass 1: truncate long text fields (including location, rule_id, source) to 200 chars
            for f in result_to_save.all_findings:
                _truncate_finding(f, 200)
            for cat_res in result_to_save.categories.values():
                for f in cat_res.findings:
                    _truncate_finding(f, 200)
            json_str = result_to_save.model_dump_json(indent=2)

        # Pass 2: slice findings list until <= 10MB or 0 findings left
        while (
            len(json_str.encode("utf-8")) > MAX_FILE_BYTES
            and len(result_to_save.all_findings) > 0
        ):
            new_len = len(result_to_save.all_findings) // 2
            result_to_save.all_findings = result_to_save.all_findings[:new_len]
            for cat_enum, cat_res in result_to_save.categories.items():
                cat_res.findings = [
                    f for f in result_to_save.all_findings if f.category == cat_enum
                ]
            _sync_findings_counts(result_to_save)
            json_str = result_to_save.model_dump_json(indent=2)

        # Pass 3: aggressive string truncation if still > 10MB (even with 0 findings)
        if len(json_str.encode("utf-8")) > MAX_FILE_BYTES:
            _truncate_top_level_strings(result_to_save, 50)
            for f in result_to_save.all_findings:
                _truncate_finding(f, 50)
            for cat_res in result_to_save.categories.values():
                for f in cat_res.findings:
                    _truncate_finding(f, 50)
                if getattr(cat_res, "summary", None) and len(cat_res.summary) > 50:
                    cat_res.summary = cat_res.summary[:50] + "..."
            _sync_findings_counts(result_to_save)
            json_str = result_to_save.model_dump_json(indent=2)

        encoded_bytes = json_str.encode("utf-8")
        if len(encoded_bytes) > MAX_FILE_BYTES:
            logger.warning(
                "Scan result JSON exceeds 10MB after Pass 3. Clearing findings to guarantee limit."
            )
            result_to_save.all_findings = []
            for cat_res in result_to_save.categories.values():
                cat_res.findings = []
            _sync_findings_counts(result_to_save)
            json_str = result_to_save.model_dump_json(indent=2)
            encoded_bytes = json_str.encode("utf-8")

        with open(target_path, "wb") as f:
            f.write(encoded_bytes)

        logger.info(f"Saved scan result JSON to: {target_path}")
        return target_path
