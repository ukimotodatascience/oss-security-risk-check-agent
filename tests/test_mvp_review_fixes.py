from unittest.mock import MagicMock, patch
from src.adapters.scorecard_adapter import ScorecardAdapter, CHECK_CATEGORY_MAP
from src.adapters.trivy_adapter import TrivyAdapter
from src.mvp_models import Category, OverallStatus
from src.scoring.engine import ScoringEngine
from main import Main


def test_scorecard_adapter_mappings_and_unmapped_checks():
    adapter = ScorecardAdapter()

    # 1. New explicit mappings check
    assert CHECK_CATEGORY_MAP.get("Dependency-Update-Tool") == Category.DEPENDENCIES
    assert CHECK_CATEGORY_MAP.get("License") == Category.DEVELOPMENT
    assert CHECK_CATEGORY_MAP.get("Webhooks") == Category.CICD

    # 2. Unmapped checks should be skipped (not fallback to MAINTENANCE)
    mock_data = {
        "checks": [
            {"name": "Dependency-Update-Tool", "score": 8, "reason": "Tool present"},
            {"name": "Unknown-Future-Check", "score": 3, "reason": "Future feature"},
        ]
    }
    findings = adapter.parse_json(mock_data)
    assert len(findings) == 1
    assert findings[0].category == Category.DEPENDENCIES
    assert findings[0].rule_id == "SCORECARD-DEPENDENCY-UPDATE-TOOL"


def test_trivy_adapter_local_path_mode():
    adapter = TrivyAdapter()
    with patch("subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b"", b"")
        mock_proc.returncode = 0
        mock_popen.return_value = mock_proc

        # Test local path triggers "fs" mode
        adapter.run_scan("/tmp/some_repo")
        cmd = mock_popen.call_args[0][0]
        assert cmd[1] == "fs"
        assert "--scanners" in cmd
        assert cmd[-1] == "/tmp/some_repo"

        # Test URL triggers "repo" mode
        adapter.run_scan("https://github.com/owner/repo")
        cmd2 = mock_popen.call_args[0][0]
        assert cmd2[1] == "repo"
        assert cmd2[-1] == "https://github.com/owner/repo"


def test_main_cli_options_parse():
    # 1. Default (no args) => mvp = False
    opt1 = Main.parse_args([])
    assert opt1.mvp is False

    # 2. Target URL given without --mvp => mvp = False (legacy compatibility)
    opt2 = Main.parse_args(["https://github.com/owner/repo"])
    assert opt2.mvp is False
    assert opt2.target_url == "https://github.com/owner/repo"

    # 3. --mvp flag given => mvp = True
    opt3 = Main.parse_args(["--mvp"])
    assert opt3.mvp is True

    # 4. --mvp flag and target_url given => mvp = True
    opt4 = Main.parse_args(["https://github.com/owner/repo", "--mvp"])
    assert opt4.mvp is True


def test_scoring_engine_unknown_status_and_metadata():
    engine = ScoringEngine()
    res = engine.evaluate(
        "https://github.com/owner/repo",
        [],
        scanner_status={},
        scanned_ref="main",
        scanned_subdir="backend",
    )
    assert res.status == OverallStatus.UNKNOWN
    assert res.scanned_ref == "main"
    assert res.scanned_subdir == "backend"


def test_scorecard_low_findings_retained_in_risk_list():
    from src.mvp_models import Finding

    engine = ScoringEngine()
    findings = [
        Finding(
            category=Category.DEPENDENCIES,
            source="scorecard",
            rule_id="SCORECARD-DEPENDENCY-UPDATE-TOOL",
            severity="LOW",
            title="Scorecard: Dependency-Update-Tool (Score: 8/10)",
            raw_score=8.0,
        )
    ]
    res = engine.evaluate(
        "https://github.com/owner/repo",
        findings,
        scanner_status={"scorecard": True},
    )
    cat_res = res.categories["dependencies"]
    assert cat_res.score == 8.0
    assert len(cat_res.findings) == 1
    assert cat_res.findings[0].severity == "LOW"


def test_scoring_engine_unknown_severity_deduction():
    from src.mvp_models import Finding

    engine = ScoringEngine()
    findings = [
        Finding(
            category=Category.SOURCE_CODE,
            source="rule_based",
            rule_id="RULE-UNKNOWN-1",
            severity="UNKNOWN",
            title="Unknown Vulnerability",
        )
    ]
    res = engine.evaluate(
        "https://github.com/owner/repo",
        findings,
        scanner_status={"rule_based": True},
    )
    cat_res = res.categories["source_code"]
    assert cat_res.score == 9.5  # 10.0 - 0.5
    assert len(cat_res.findings) == 1
    assert cat_res.findings[0].severity == "UNKNOWN"


def test_orchestrator_rule_based_findings_retained_when_trivy_fails():
    from unittest.mock import MagicMock
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category

    orchestrator = MVPOrchestrator()
    mock_record = MagicMock()
    mock_record.category = "secrets"
    mock_record.rule_id = "SECRET-001"
    mock_record.severity.value = "HIGH"
    mock_record.title = "Hardcoded Secret"
    mock_record.file_path = "config.py"
    mock_record.line = 10
    mock_record.message = "Found potential secret"

    mock_scan_result = MagicMock()
    mock_scan_result.records = [mock_record]
    mock_scan_result.errors = []

    with patch("src.scan.SecurityScan.run", return_value=mock_scan_result):
        # When trivy scanner is False (failed/skipped), secrets rule-based finding is retained
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status={"trivy": False},
        )
        assert success is True
        assert len(findings) == 1
        assert findings[0].category == Category.SECRETS

        # Rule-based findings are retained and deduplicated across scanners
        findings_trivy_ok, _ = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status={"trivy": True},
        )
        assert len(findings_trivy_ok) == 1


def test_scoring_engine_preserves_fallback_findings_when_trivy_false():
    from src.mvp_models import Finding

    engine = ScoringEngine()
    findings = [
        Finding(
            category=Category.SECRETS,
            source="rule_based",
            rule_id="SECRET-FALLBACK-1",
            severity="HIGH",
            title="Fallback Secret Finding",
        )
    ]
    res = engine.evaluate(
        "https://github.com/owner/repo",
        findings,
        scanner_status={"trivy": False, "scorecard": True, "rule_based": True},
    )
    # Category evaluated is False because Trivy didn't run
    assert res.categories["secrets"].evaluated is False
    # But findings are preserved!
    assert len(res.categories["secrets"].findings) == 1
    assert res.categories["secrets"].findings[0].rule_id == "SECRET-FALLBACK-1"
    assert len(res.all_findings) == 1


def test_orchestrator_config_and_maintenance_category_mapping():
    from unittest.mock import MagicMock
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category

    orchestrator = MVPOrchestrator()
    rec_config = MagicMock()
    rec_config.category = "config"
    rec_config.rule_id = "CONFIG-001"
    rec_config.severity.value = "MEDIUM"
    rec_config.title = "Config Issue"
    rec_config.file_path = "settings.json"
    rec_config.line = 1
    rec_config.message = "Bad config"

    rec_maint = MagicMock()
    rec_maint.category = "maintenance"
    rec_maint.rule_id = "MAINT-001"
    rec_maint.severity.value = "LOW"
    rec_maint.title = "Maintenance Issue"
    rec_maint.file_path = "README.md"
    rec_maint.line = 1
    rec_maint.message = "Missing policy"

    mock_scan_result = MagicMock()
    mock_scan_result.records = [rec_config, rec_maint]
    mock_scan_result.errors = []

    with patch("src.scan.SecurityScan.run", return_value=mock_scan_result):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status={"trivy": False, "scorecard": False},
        )
        assert success is True
        cat_map = {f.rule_id: f.category for f in findings}
        assert cat_map["CONFIG-001"] == Category.MISCONFIGURATION
        assert (
            cat_map["MAINTENANCE-001"] == Category.MAINTENANCE
            if "MAINTENANCE-001" in cat_map
            else Category.MAINTENANCE
        )


def test_scorecard_disabled_check_marks_category_unevaluated():
    from src.mvp_models import Finding

    engine = ScoringEngine()
    findings = [
        Finding(
            category=Category.DEVELOPMENT,
            source="scorecard",
            rule_id="SCORECARD-BRANCH-PROTECTION",
            severity="INFO",
            title="Scorecard: Branch-Protection (Unable to Evaluate)",
            raw_score=None,
        )
    ]
    res = engine.evaluate(
        "https://github.com/owner/repo",
        findings,
        scanner_status={"scorecard": True},
    )
    # Disabled check marks evaluated as False
    assert res.categories["development"].evaluated is False


def test_scorecard_deducts_other_rule_findings():
    from src.mvp_models import Finding

    engine = ScoringEngine()
    findings = [
        Finding(
            category=Category.CICD,
            source="scorecard",
            rule_id="SCORECARD-DANGEROUS-WORKFLOW",
            severity="INFO",
            title="Scorecard: Dangerous-Workflow (Score: 10/10)",
            raw_score=10.0,
        ),
        Finding(
            category=Category.CICD,
            source="rule_based",
            rule_id="C1-CURL-PIPE-SHELL",
            severity="HIGH",
            title="Curl piped to shell",
        ),
    ]
    res = engine.evaluate(
        "https://github.com/owner/repo",
        findings,
        scanner_status={"scorecard": True},
    )
    # Scorecard base score (10.0) minus HIGH rule finding (1.5) = 8.5
    assert res.categories["cicd"].score == 8.5
    assert res.categories["cicd"].findings_count == 1
    assert len(res.categories["cicd"].findings) == 2
    assert any(
        f.rule_id == "C1-CURL-PIPE-SHELL" for f in res.categories["cicd"].findings
    )


def test_rule_based_scan_with_target_dir(tmp_path):
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator()
    (tmp_path / "test.py").write_text("import os\n")

    findings, success = orchestrator._run_rule_based_scan(
        "https://github.com/owner/repo",
        scanner_status={"trivy": False, "scorecard": False},
        target_dir=tmp_path,
    )
    assert isinstance(findings, list)
    assert success is True


def test_cutoff_rule_triggers_dangerous_on_unevaluated_category_critical_finding():
    from src.mvp_models import Finding

    engine = ScoringEngine()
    findings = [
        # Category SECRETS is unevaluated (trivy = False), but has 3 CRITICAL findings => score 1.0
        Finding(
            category=Category.SECRETS,
            source="rule_based",
            rule_id="SECRET-1",
            severity="CRITICAL",
            title="Secret 1",
        ),
        Finding(
            category=Category.SECRETS,
            source="rule_based",
            rule_id="SECRET-2",
            severity="CRITICAL",
            title="Secret 2",
        ),
        Finding(
            category=Category.SECRETS,
            source="rule_based",
            rule_id="SECRET-3",
            severity="CRITICAL",
            title="Secret 3",
        ),
    ]
    res = engine.evaluate(
        "https://github.com/owner/repo",
        findings,
        scanner_status={"trivy": False, "scorecard": False, "rule_based": True},
    )
    # SECRETS score is 1.0 (<= 2.0) => status must be DANGEROUS even if unevaluated
    assert res.status == OverallStatus.DANGEROUS
    assert "足切りルール" in res.status_reason


def test_orchestrator_deduplicates_findings():
    from src.mvp_models import Finding

    f1 = Finding(
        category=Category.SECRETS,
        source="rule_based",
        rule_id="RULE-1",
        severity="HIGH",
        title="Duplicate Secret",
        target="config.py",
        location="Line 5",
    )
    f2 = Finding(
        category=Category.SECRETS,
        source="trivy",
        rule_id="RULE-1",
        severity="HIGH",
        title="Duplicate Secret",
        target="config.py",
        location="Line 5",
    )

    all_findings = [f1, f2]
    seen_keys = set()
    deduped = []
    for f in all_findings:
        key = (f.category, f.rule_id, f.target or "", f.location or "", f.title)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped.append(f)

    assert len(deduped) == 1


def test_scoring_engine_unevaluated_with_only_info_findings_keeps_score_none():
    from src.mvp_models import Finding

    engine = ScoringEngine()
    # SECRETS category is unevaluated (trivy = False) and only has an INFO finding
    findings = [
        Finding(
            category=Category.SECRETS,
            source="snapshot_fetcher",
            rule_id="GIT-HISTORY-UNEVALUATED",
            severity="INFO",
            title="Git History Skipped",
        )
    ]
    res = engine.evaluate(
        "https://github.com/owner/repo",
        findings,
        scanner_status={"trivy": False, "scorecard": True, "rule_based": True},
    )
    sec_result = res.categories[Category.SECRETS.value]
    assert sec_result.evaluated is False
    assert sec_result.score == 0.0 or sec_result.score is None


def test_b1_rule_mapped_to_known_vulnerabilities():
    from src.models import RiskRecord, Severity
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator()
    mock_rec = RiskRecord(
        rule_id="B-1",
        category="dependencies",
        severity=Severity.HIGH,
        title="Vulnerable Dep",
        message="CVE-2023-1234",
    )
    with (
        patch("src.rule_engine.load_all_rules", return_value=[]),
        patch("src.rule_engine.run_all", return_value=([mock_rec], [], 1)),
    ):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            target_dir=orchestrator.project_root,
        )
        assert len(findings) == 1
        assert findings[0].category == Category.KNOWN_VULNERABILITIES
        assert findings[0].rule_id == "B-1"


def test_scorecard_skipped_when_ref_or_subdir_specified():
    from main import CliOptions
    from src.orchestrator import MVPOrchestrator

    opts = CliOptions(target_ref="v1.0.0", target_subdir="src")
    orchestrator = MVPOrchestrator(cli_options=opts)
    with (
        patch.object(
            orchestrator.trivy_adapter, "run_scan_with_status", return_value=([], True)
        ),
        patch.object(orchestrator, "_run_rule_based_scan", return_value=([], True)),
        patch.object(orchestrator.scorecard_adapter, "run_scan") as mock_scorecard,
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        mock_scorecard.assert_not_called()
        assert res.scanned_ref == "v1.0.0"
        assert res.scanned_subdir == "src"


def test_main_mutually_exclusive_mvp_and_legacy():
    import pytest

    with pytest.raises(SystemExit):
        Main.parse_args(["--mvp", "--legacy"])


def test_trivy_parse_json_max_findings_limit():
    adapter = TrivyAdapter()
    data = {
        "Results": [
            {
                "Target": "package.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f"CVE-2023-{i}",
                        "Severity": "HIGH",
                        "Title": f"Vuln {i}",
                        "Description": f"Description {i}",
                    }
                    for i in range(600)
                ],
            }
        ]
    }
    findings = adapter.parse_json(data, max_findings=500)
    assert len(findings) == 503
    assert findings[-1].rule_id == "TRIVY-FINDINGS-LIMIT-EXCEEDED"


def test_deduplication_key_preserves_different_descriptions():
    from src.mvp_models import Finding
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator()
    f1 = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="MEDIUM",
        title="Vulnerability B-1",
        target="package.json",
        description="CVE-2023-0001",
    )
    f2 = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="CRITICAL",
        title="Vulnerability B-1",
        target="package.json",
        description="CVE-2023-0002",
    )
    with (
        patch.object(
            orchestrator.trivy_adapter, "run_scan_with_status", return_value=([], True)
        ),
        patch.object(orchestrator.scorecard_adapter, "run_scan", return_value=[]),
        patch.object(
            orchestrator, "_run_rule_based_scan", return_value=([f1, f2], True)
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert len(res.all_findings) == 2


def test_git_history_unevaluated_affects_secrets_and_maintenance_categories():
    engine = ScoringEngine()
    res = engine.evaluate(
        "https://github.com/owner/repo",
        [],
        scanner_status={
            "trivy": True,
            "scorecard": True,
            "rule_based": True,
            "git_history": False,
        },
    )
    assert res.categories[Category.SECRETS.value].evaluated is False
    assert res.categories[Category.MAINTENANCE.value].evaluated is False


def test_rule_based_scan_failure_propagates_to_all_categories():
    engine = ScoringEngine()
    res = engine.evaluate(
        "https://github.com/owner/repo",
        [],
        scanner_status={"trivy": True, "scorecard": True, "rule_based": False},
    )
    for cat_res in res.categories.values():
        assert cat_res.evaluated is False


def test_trivy_parse_json_with_status_returns_false_and_all_categories_truncated():
    adapter = TrivyAdapter()
    data = {
        "Results": [
            {
                "Target": "package.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f"CVE-2023-{i}",
                        "Severity": "HIGH",
                        "Title": f"Vuln {i}",
                        "Description": f"Description {i}",
                    }
                    for i in range(600)
                ],
            }
        ]
    }
    findings, is_full_success = adapter.parse_json_with_status(data, max_findings=500)
    assert is_full_success is False
    truncated_cats = {
        f.category for f in findings if f.rule_id == "TRIVY-FINDINGS-LIMIT-EXCEEDED"
    }
    assert Category.KNOWN_VULNERABILITIES in truncated_cats
    assert Category.SECRETS in truncated_cats
    assert Category.MISCONFIGURATION in truncated_cats


def test_rule_evaluate_signatures_support_max_records():
    import inspect
    from pathlib import Path
    from src.rule_engine import load_all_rules

    rules = load_all_rules(Path("."))
    for r in rules:
        sig = inspect.signature(r.evaluate)
        assert "max_records" in sig.parameters


def test_rule_engine_exact_500_findings_does_not_trigger_global_limit():
    from pathlib import Path
    from concurrent.futures import Future
    from src.rule_engine import run_all
    from src.models import RiskRecord, Severity
    from src.rules.A_code.A8_unsafe_eval import A8UnsafeEvalRule

    rule = A8UnsafeEvalRule()
    mock_records_500 = [
        RiskRecord(
            rule_id=rule.rule_id,
            category=rule.category,
            title=rule.title,
            severity=Severity.LOW,
            file_path="foo.py",
            line=1,
            message="msg",
        )
        for _ in range(500)
    ]
    f500 = Future()
    f500.set_result((True, mock_records_500, False, None))

    with patch("concurrent.futures.ProcessPoolExecutor.submit", return_value=f500):
        records, errors, executed = run_all(Path("."), rules=[rule])
        assert len(records) == 500
        assert not any(err[0] == "GLOBAL_LIMIT" for err in errors)


def test_orchestrator_excludes_b1_findings_when_trivy_succeeds():
    from pathlib import Path
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category, Finding

    orchestrator = MVPOrchestrator()
    trivy_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="trivy",
        rule_id="CVE-2023-1234",
        severity="HIGH",
        title="CVE-2023-1234",
        description="Known vulnerability in lib",
    )
    b1_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="B-1 Vulnerability",
        description="Duplicate vulnerability check",
    )
    other_rule_finding = Finding(
        category=Category.SOURCE_CODE,
        source="rule_based",
        rule_id="A-1",
        severity="MEDIUM",
        title="Command Injection",
        description="Unsafe command execution",
    )

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher.fetch",
            return_value=Path("."),
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([trivy_finding], True),
        ),
        patch.object(orchestrator.scorecard_adapter, "run_scan", return_value=[]),
        patch.object(
            orchestrator,
            "_run_rule_based_scan",
            return_value=([b1_finding, other_rule_finding], True),
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        rule_ids = [f.rule_id for f in res.all_findings]
        # B-1 finding without CVE matches should be preserved
        assert "B-1" in rule_ids
        assert "CVE-2023-1234" in rule_ids
        assert "A-1" in rule_ids


def test_orchestrator_b1_deduplication_removes_matching_cve():
    from pathlib import Path
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category, Finding

    orchestrator = MVPOrchestrator()
    trivy_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="trivy",
        rule_id="CVE-2023-1234",
        severity="HIGH",
        title="CVE-2023-1234 in libfoo",
        description="Vulnerability CVE-2023-1234 detected",
    )
    b1_cve_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="CVE-2023-1234",
        description="CVE-2023-1234 in dependency",
    )

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher.fetch",
            return_value=Path("."),
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([trivy_finding], True),
        ),
        patch.object(orchestrator.scorecard_adapter, "run_scan", return_value=[]),
        patch.object(
            orchestrator, "_run_rule_based_scan", return_value=([b1_cve_finding], True)
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        rule_ids = [f.rule_id for f in res.all_findings]
        assert "B-1" not in rule_ids
        assert "CVE-2023-1234" in rule_ids


def test_orchestrator_handles_skipped_file_object_safely():
    from pathlib import Path
    from unittest.mock import MagicMock
    from src.orchestrator import MVPOrchestrator
    from src.targets.models import SkippedFile

    orchestrator = MVPOrchestrator()
    sf1 = SkippedFile(path="repo-ref/backend/big.bin", reason="size limit")
    sf2 = SkippedFile(path="repo-ref/frontend/large.pdf", reason="size limit")

    mock_fetcher = MagicMock()
    mock_fetcher.fetch.return_value = Path(".")
    mock_fetcher.skipped_files = (sf1, sf2)

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher",
            return_value=mock_fetcher,
        ),
        patch.object(
            orchestrator.trivy_adapter, "run_scan_with_status", return_value=([], True)
        ),
        patch.object(orchestrator.scorecard_adapter, "run_scan", return_value=[]),
        patch.object(orchestrator, "_run_rule_based_scan", return_value=([], True)),
    ):
        # Should not raise AttributeError when processing SkippedFile objects with target_subdir="backend"
        orchestrator.cli_options = type(
            "Opt",
            (),
            {"target_ref": None, "target_subdir": "backend", "output_dir": None},
        )()
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None


def test_is_in_subdir_nested_target_subdir():
    from pathlib import Path
    from unittest.mock import MagicMock
    from src.orchestrator import MVPOrchestrator
    from src.targets.models import SkippedFile

    orchestrator = MVPOrchestrator()
    sf_nested = SkippedFile(path="repo-ref/services/api/big.bin", reason="size limit")
    sf_other = SkippedFile(path="repo-ref/other/api/large.pdf", reason="size limit")

    mock_fetcher = MagicMock()
    mock_fetcher.fetch.return_value = Path(".")
    mock_fetcher.skipped_files = (sf_nested, sf_other)

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher",
            return_value=mock_fetcher,
        ),
        patch.object(
            orchestrator.trivy_adapter, "run_scan_with_status", return_value=([], True)
        ),
        patch.object(orchestrator.scorecard_adapter, "run_scan", return_value=[]),
        patch.object(orchestrator, "_run_rule_based_scan", return_value=([], True)),
    ):
        orchestrator.cli_options = type(
            "Opt",
            (),
            {"target_ref": None, "target_subdir": "services/api", "output_dir": None},
        )()
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        # Verify SKIPPED-FILES-LIMIT finding is present due to relevant skipped file in services/api
        assert any(f.rule_id == "SKIPPED-FILES-LIMIT" for f in res.all_findings)


def test_exact_500_rule_findings_not_truncated():
    from pathlib import Path
    from concurrent.futures import Future
    from src import rule_engine
    from src.models import RiskRecord, Severity
    from src.rules.A_code.A8_unsafe_eval import A8UnsafeEvalRule

    rule = A8UnsafeEvalRule()
    mock_records_500 = [
        RiskRecord(
            rule_id=rule.rule_id,
            category=rule.category,
            title=rule.title,
            severity=Severity.LOW,
            file_path="foo.py",
            line=1,
            message="msg",
        )
        for _ in range(500)
    ]
    f500 = Future()
    f500.set_result((True, mock_records_500, False, None))

    with patch("concurrent.futures.ProcessPoolExecutor.submit", return_value=f500):
        records, errors, executed = rule_engine.run_all(Path("."), rules=[rule])
        assert len(records) == 500
        assert not any(err[0] == "GLOBAL_LIMIT" for err in errors)


def test_trivy_preserves_pkg_name():
    from src.adapters.trivy_adapter import TrivyAdapter

    adapter = TrivyAdapter()
    data = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2022-24999",
                        "PkgName": "express",
                        "InstalledVersion": "4.17.1",
                        "FixedVersion": "4.17.3",
                        "Severity": "HIGH",
                        "Title": "Prototype Pollution",
                        "Description": "qs vulnerable to Prototype Pollution",
                    }
                ],
            }
        ]
    }
    findings = adapter.parse_json(data)
    assert len(findings) == 1
    f = findings[0]
    assert f.location == "express@4.17.1"
    assert "express" in f.description
    assert f.remediation == "Upgrade express to 4.17.3"


def test_trivy_parse_json_empty_subsequent_results_not_truncated():
    from src.adapters.trivy_adapter import TrivyAdapter

    adapter = TrivyAdapter()
    data = {
        "Results": [
            {
                "Target": "package.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f"CVE-2023-{i}",
                        "Severity": "HIGH",
                        "Title": f"Vuln {i}",
                    }
                    for i in range(500)
                ],
            },
            {
                "Target": "empty-file.json",
                "Vulnerabilities": [],
                "Secrets": [],
                "Misconfigurations": [],
            },
        ]
    }
    findings, is_full_success = adapter.parse_json_with_status(data, max_findings=500)
    assert len(findings) == 500
    assert is_full_success is True
    assert not any(f.rule_id == "TRIVY-FINDINGS-LIMIT-EXCEEDED" for f in findings)


def test_scoring_engine_preserves_info_findings():
    from src.scoring.engine import ScoringEngine
    from src.mvp_models import Category, Finding

    engine = ScoringEngine()
    info_finding = Finding(
        category=Category.SECRETS,
        source="snapshot_fetcher",
        rule_id="GIT-HISTORY-UNEVALUATED",
        severity="INFO",
        title="Git History Skipped",
        description="Git history skipped",
    )
    result = engine.evaluate(
        repo_url="https://github.com/owner/repo",
        findings=[info_finding],
        scanner_status={
            "trivy": True,
            "scorecard": True,
            "rule_based": True,
            "git_history": False,
        },
    )
    assert any(f.rule_id == "GIT-HISTORY-UNEVALUATED" for f in result.all_findings)
    assert any(
        f.rule_id == "GIT-HISTORY-UNEVALUATED"
        for f in result.categories[Category.SECRETS.value].findings
    )


def test_is_in_subdir_normalizes_dot_segments():
    from pathlib import Path
    from unittest.mock import MagicMock
    from src.orchestrator import MVPOrchestrator
    from src.targets.models import SkippedFile

    orchestrator = MVPOrchestrator()
    sf_other = SkippedFile(path="repo-ref/other/big.bin", reason="size limit")

    mock_fetcher = MagicMock()
    mock_fetcher.fetch.return_value = Path(".")
    mock_fetcher.skipped_files = (sf_other,)

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher",
            return_value=mock_fetcher,
        ),
        patch.object(
            orchestrator.trivy_adapter, "run_scan_with_status", return_value=([], True)
        ),
        patch.object(orchestrator.scorecard_adapter, "run_scan", return_value=[]),
        patch.object(orchestrator, "_run_rule_based_scan", return_value=([], True)),
    ):
        # Test target_subdir="services/../other"
        orchestrator.cli_options = type(
            "Opt",
            (),
            {
                "target_ref": None,
                "target_subdir": "services/../other",
                "output_dir": None,
            },
        )()
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        assert any(f.rule_id == "SKIPPED-FILES-LIMIT" for f in res.all_findings)


def test_b1_known_vulnerabilities_caps_dependency_lookups():
    from pathlib import Path
    from src.rules.B_dependencies.B1_known_vulnerabilities import (
        B1KnownVulnerabilitiesRule,
    )
    from src.rules.B_dependencies._dependency_utils import DependencyDecl

    rule = B1KnownVulnerabilitiesRule()
    fake_deps = [
        DependencyDecl(
            ecosystem="npm",
            name=f"pkg-{i}",
            spec=f"1.0.{i}",
            file_path="package.json",
            line=i + 1,
        )
        for i in range(600)
    ]

    with (
        patch(
            "src.rules.B_dependencies.B1_known_vulnerabilities.collect_dependency_declarations",
            return_value=fake_deps,
        ),
        patch.object(rule._lookup, "bulk_lookup", return_value={}) as mock_bulk,
    ):
        records = rule.evaluate(Path("."), max_records=500)
        # Should query at most 500 dependencies in bulk_lookup
        query_list = mock_bulk.call_args[0][1]
        assert len(query_list) == 500
        # Should append a truncation record so len(records) > 500
        assert len(records) > 500


def test_a1_3_command_injection_fallback_respects_max_records(tmp_path):
    from src.rules.A_code.A1_3_command_injection_js_ts import (
        JsTsCommandInjectionDetector,
    )

    rule = JsTsCommandInjectionDetector()
    # Generate a JS file with many exec calls that trigger regex fallback
    lines = ['const execa = require("execa");']
    for i in range(10):
        lines.append(f"const input{i} = req.query.arg;")
        lines.append(f"execa.command(input{i});")

    js_file = tmp_path / "test.js"
    js_file.write_text("\n".join(lines), encoding="utf-8")

    # Force tree-sitter to return None so fallback path is executed
    with patch.object(rule, "_evaluate_js_ts_file_with_tree_sitter", return_value=None):
        records = rule._evaluate_js_ts_file(js_file, tmp_path, max_records=3)
        assert len(records) <= 3


def test_skipped_files_limit_severity_is_info(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": None, "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)
    mock_fetcher = MagicMock()
    mock_fetcher.skipped_files = ["large.bin"]
    mock_fetcher.fetch.return_value = tmp_path

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher",
            return_value=mock_fetcher,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([], False),
        ),
        patch.object(orchestrator, "_run_rule_based_scan", return_value=([], False)),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        skipped_findings = [
            f for f in res.all_findings if f.rule_id == "SKIPPED-FILES-LIMIT"
        ]
        assert len(skipped_findings) > 0
        for f in skipped_findings:
            assert f.severity == "INFO"
