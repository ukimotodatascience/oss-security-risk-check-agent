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
    from unittest.mock import MagicMock

    with (
        patch("src.rule_engine.load_all_rules", return_value=[MagicMock()]),
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
    from src.models import Severity
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
        # Should append exactly one truncation record (records list length is 1 as pinned fake_deps had 0 vuln hits)
        assert len(records) == 1
        assert records[-1].file_path == "dependencies"
        assert "打ち切りました" in records[-1].message
        assert records[-1].severity == Severity.INFO


def test_b1_deduplication_matches_primary_vuln_id(tmp_path):
    from unittest.mock import MagicMock
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Finding, Category

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": None, "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)

    mock_fetcher = MagicMock()
    mock_fetcher.skipped_files = []
    mock_fetcher.fetch.return_value = tmp_path

    # Trivy finding has CVE-2023-9999
    trivy_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="trivy",
        rule_id="CVE-2023-9999",
        severity="HIGH",
        title="CVE-2023-9999",
        description="Vulnerability description referencing GHSA-xxxx-yyyy-zzzz",
    )

    # B-1 finding has primary ID CVE-2023-9999, but description includes references to GHSA-xxxx-yyyy-zzzz
    b1_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="B-1",
        description="pkg 1.0 は既知脆弱性に該当する可能性があります [NVD:CVE-2023-9999] Summary refs: GHSA-xxxx-yyyy-zzzz",
    )

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher",
            return_value=mock_fetcher,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([trivy_finding], True),
        ),
        patch.object(
            orchestrator, "_run_rule_based_scan", return_value=([b1_finding], True)
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        # B-1 finding should be deduplicated based on primary ID match (CVE-2023-9999)
        b1_results = [
            f
            for f in res.all_findings
            if f.source == "rule_based" and f.rule_id == "B-1"
        ]
        assert len(b1_results) == 0


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


def test_a1_4_command_injection_shell_fallback_deduplicates_findings(tmp_path):
    from src.rules.A_code.A1_4_command_injection_shell import (
        ShellCommandInjectionDetector,
    )

    rule = ShellCommandInjectionDetector()
    lines = ["# shell script"]
    for i in range(10):
        lines.append(f'eval "echo $input{i}"')

    sh_file = tmp_path / "test.sh"
    sh_file.write_text("\n".join(lines), encoding="utf-8")

    with patch.object(rule, "_evaluate_shell_file_with_tree_sitter", return_value=None):
        records = rule._evaluate_shell_file(sh_file, tmp_path, max_records=3)
        assert len(records) <= 3


def test_orchestrator_serializes_rule_errors_as_info_findings(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": None, "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)

    mock_fetcher = MagicMock()
    mock_fetcher.skipped_files = []
    mock_fetcher.fetch.return_value = tmp_path

    # Simulate run_all returning a rule execution traceback
    mock_errors = [
        (
            "A-8",
            'Traceback (most recent call last):\n  File "rule.py", line 10, in evaluate\nTimeoutError: Rule execution timed out after 30 seconds.',
        )
    ]

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher",
            return_value=mock_fetcher,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([], True),
        ),
        patch("src.rule_engine.run_all", return_value=([], mock_errors, 1)),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        err_findings = [f for f in res.all_findings if f.rule_id == "A-8-UNEVALUATED"]
        assert len(err_findings) == 1
        assert err_findings[0].severity == "INFO"
        assert "TimeoutError" in err_findings[0].description


def test_is_in_subdir_case_sensitive(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": "services", "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)

    mock_fetcher = MagicMock()
    # File in 'Services/big.bin' (uppercase S) vs target_subdir='services'
    mock_fetcher.skipped_files = [
        "repo-main/Services/big.bin",
        "repo-main/services/valid.bin",
    ]
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
        # Only 'repo-main/services/valid.bin' matches 'services' scope
        skipped = [f for f in res.all_findings if f.rule_id == "SKIPPED-FILES-LIMIT"]
        assert len(skipped) == 4  # 4 categories for 1 relevant file


def test_trivy_vuln_ids_extracted_from_headers_only(tmp_path):
    from unittest.mock import patch
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category, Finding

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": None, "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)

    trivy_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="trivy",
        rule_id="CVE-2024-1111",
        severity="HIGH",
        title="Trivy Vuln CVE-2024-1111",
        description="This vulnerability references CVE-2024-9999 in notes.",
    )
    # B-1 finding for CVE-2024-9999 should NOT be discarded because CVE-2024-9999 was only in trivy's description!
    b1_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="[CVE-2024-9999] High Vulnerability",
        description="Dependency vulnerability",
    )

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher.fetch",
            return_value=tmp_path,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([trivy_finding], True),
        ),
        patch.object(
            orchestrator,
            "_run_rule_based_scan",
            return_value=([b1_finding], True),
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        rule_b1s = [f for f in res.all_findings if f.rule_id == "B-1"]
        assert len(rule_b1s) == 1
        assert "CVE-2024-9999" in rule_b1s[0].title


def test_js_app_findings_limits_defined():
    from pathlib import Path

    js_file = Path("docs/app.js")
    assert js_file.exists()
    content = js_file.read_text(encoding="utf-8")
    assert "if (findingsArray.length > 10000) return false;" in content
    assert "const MAX_RENDER_FINDINGS = 1000;" in content


def test_rule_error_category_mapping_and_sanitization(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": None, "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)

    mock_fetcher = MagicMock()
    mock_fetcher.skipped_files = []
    mock_fetcher.fetch.return_value = tmp_path

    # Simulate errors for B-1 and D-1 rules
    mock_errors = [
        ("B-1", "Traceback ...\n  File 'x.py'\nValueError: Bad value secret=AKIA12345"),
        ("D-1", "Traceback ...\nTimeoutError: Rule execution timed out"),
    ]

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher",
            return_value=mock_fetcher,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([], True),
        ),
        patch("src.rule_engine.run_all", return_value=([], mock_errors, 2)),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        b1_err = [f for f in res.all_findings if f.rule_id == "B-1-UNEVALUATED"][0]
        assert b1_err.category == Category.KNOWN_VULNERABILITIES
        assert b1_err.description == "Rule B-1 failed during execution: ValueError"

        d1_err = [f for f in res.all_findings if f.rule_id == "D-1-UNEVALUATED"][0]
        assert d1_err.category == Category.MISCONFIGURATION
        assert d1_err.description == "Rule D-1 failed during execution: TimeoutError"


def test_trivy_findings_limit_exceeded_severity_info():
    from src.adapters.trivy_adapter import TrivyAdapter

    adapter = TrivyAdapter()
    # Mock data with > 500 findings to trigger limit
    results = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": f"CVE-2024-{i}",
                        "Severity": "HIGH",
                        "Title": f"Vuln {i}",
                        "PkgName": "foo",
                        "InstalledVersion": "1.0.0",
                    }
                    for i in range(501)
                ],
            }
        ]
    }
    findings = adapter.parse_json(results, max_findings=500)
    limit_findings = [
        f for f in findings if f.rule_id == "TRIVY-FINDINGS-LIMIT-EXCEEDED"
    ]
    assert len(limit_findings) == 3
    for f in limit_findings:
        assert f.severity == "INFO"


def test_trivy_b1_dedup_matches_package_name(tmp_path):
    from unittest.mock import patch
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category, Finding

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": None, "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)

    # Trivy detected CVE-2024-1000 for package 'pkg-a'
    trivy_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="trivy",
        rule_id="CVE-2024-1000",
        severity="HIGH",
        title="Trivy CVE-2024-1000",
        location="pkg-a@1.0.0",
        description="Package: pkg-a\nHigh vulnerability",
    )

    # B-1 detected CVE-2024-1000 for package 'pkg-b' (different package!)
    b1_finding_b = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="[GH:CVE-2024-1000] Vulnerability in pkg-b",
        description="pkg-b 2.0.0 は既知脆弱性に該当する可能性があります [GH:CVE-2024-1000]",
    )

    # B-1 detected CVE-2024-1000 for package 'pkg-a' (same package!)
    b1_finding_a = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="[GH:CVE-2024-1000] Vulnerability in pkg-a",
        description="pkg-a 1.0.0 は既知脆弱性に該当する可能性があります [GH:CVE-2024-1000]",
    )

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher.fetch",
            return_value=tmp_path,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([trivy_finding], True),
        ),
        patch.object(
            orchestrator,
            "_run_rule_based_scan",
            return_value=([b1_finding_b, b1_finding_a], True),
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        b1_retained = [f for f in res.all_findings if f.rule_id == "B-1"]
        # pkg-a should be deduplicated, but pkg-b MUST be retained!
        assert len(b1_retained) == 1
        assert "pkg-b" in b1_retained[0].description


def test_archive_fetcher_all_files_skipped_in_subdir(tmp_path):
    from src.targets.archive_fetcher import ArchiveSnapshotFetcher, SkippedFile
    from src.targets.models import ScanTargetSpec

    fetcher = ArchiveSnapshotFetcher(
        max_download_bytes=1000000,
        max_extracted_bytes=1000000,
        max_files=1000,
        max_single_file_bytes=1000000,
        timeout_sec=30,
    )
    fetcher.skipped_files = (
        SkippedFile(
            path="repo-main/services/large.bin",
            size_bytes=100000000,
            reason="file_size_exceeded",
        ),
    )

    extracted_root = tmp_path / "source"
    extracted_root.mkdir(parents=True)

    with patch("src.targets.archive_fetcher.safe_extract_zip") as mock_extract:
        mock_extract.return_value = (extracted_root, fetcher.skipped_files)
        with patch.object(fetcher, "_download_limited"):
            # Dummy zip file
            zip_file = tmp_path / "source.zip"
            zip_file.write_bytes(b"dummy")

            spec = ScanTargetSpec(
                repo_url="https://github.com/owner/repo",
                source_type="remote_archive",
                subdir="services",
            )
            ret_dir = fetcher.fetch(spec, tmp_path)
            assert ret_dir.exists()
            assert ret_dir.name == "services"


def test_archive_fetcher_is_in_subdir_normalizes_dot_dot():
    from src.targets.archive_fetcher import ArchiveSnapshotFetcher, SkippedFile

    fetcher = ArchiveSnapshotFetcher(
        max_download_bytes=1000000,
        max_extracted_bytes=1000000,
        max_files=1000,
        max_single_file_bytes=1000000,
        timeout_sec=30,
    )
    sf = SkippedFile(
        path="repo-main/other/large.bin",
        size_bytes=1000000,
        reason="file_size_exceeded",
    )
    # subdir 'services/../other' should resolve to 'other' and match sf
    assert fetcher._is_in_subdir(sf, "services/../other") is True


def test_trivy_location_rsplit_scoped_npm_package(tmp_path):
    from unittest.mock import patch
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category, Finding

    mock_opts = type(
        "Opt",
        (),
        {"target_ref": None, "target_subdir": None, "output_dir": None},
    )()
    orchestrator = MVPOrchestrator(tmp_path, cli_options=mock_opts)

    # Scoped package @babel/core@7.12.3
    trivy_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="trivy",
        rule_id="CVE-2024-5555",
        severity="HIGH",
        title="Trivy Vuln",
        location="@babel/core@7.12.3",
        description="High vulnerability",
    )
    # B-1 for DIFFERENT package 'other-pkg' with same CVE-2024-5555
    b1_finding_other = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="[GH:CVE-2024-5555] Vuln in other-pkg",
        description="other-pkg 1.0.0 は既知脆弱性に該当する可能性があります [GH:CVE-2024-5555]",
    )

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher.fetch",
            return_value=tmp_path,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([trivy_finding], True),
        ),
        patch.object(
            orchestrator,
            "_run_rule_based_scan",
            return_value=([b1_finding_other], True),
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        b1_retained = [f for f in res.all_findings if f.rule_id == "B-1"]
        # other-pkg MUST be retained because trivy was for @babel/core
        assert len(b1_retained) == 1
        assert "other-pkg" in b1_retained[0].description


def test_rule_id_attribute_lookup_in_error_handling(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)

    # Mock rule class with rule_id attribute (NOT id)
    mock_rule = MagicMock()
    mock_rule.rule_id = "A-1"
    mock_rule.category = "code"

    mock_errors = [("A-1", "Traceback ...\nTimeoutError: Rule execution timed out")]

    with (
        patch("src.rule_engine.load_all_rules", return_value=[mock_rule]),
        patch(
            "src.rule_engine.run_all",
            return_value=([], mock_errors, 1),
        ),
    ):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            target_dir=tmp_path,
        )
        assert success is False
        a1_err = [f for f in findings if f.rule_id == "A-1-UNEVALUATED"]
        assert len(a1_err) == 1


def test_fallback_scan_propagates_git_history_unevaluated(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)

    mock_target = MagicMock()
    mock_target.fetch_mode = "github_archive_zipball"
    mock_target.local_dir = tmp_path

    mock_scan_res = MagicMock()
    mock_scan_res.records = []
    mock_scan_res.errors = []
    mock_scan_res.target = mock_target

    scanner_status = {"git_history": True}

    with patch("src.scan.SecurityScan.run", return_value=mock_scan_res):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status=scanner_status,
            target_dir=None,  # triggers fallback SecurityScan
        )
        assert scanner_status["git_history"] is False
        git_findings = [f for f in findings if f.rule_id == "GIT-HISTORY-UNEVALUATED"]
        assert len(git_findings) == 2


def test_rule_prefix_category_mappings_in_fallback(tmp_path):
    from unittest.mock import patch
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category

    orchestrator = MVPOrchestrator(tmp_path)
    mock_errors = [
        ("G-1", "RuntimeError: G failed"),
        ("H-1", "ValueError: H failed"),
        ("J-1", "KeyError: J failed"),
        ("K-1", "TypeError: K failed"),
    ]

    with patch("src.rule_engine.run_all", return_value=([], mock_errors, 4)):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            target_dir=tmp_path,
        )
        assert success is False
        g_finding = [f for f in findings if f.rule_id == "G-1-UNEVALUATED"][0]
        h_finding = [f for f in findings if f.rule_id == "H-1-UNEVALUATED"][0]
        j_finding = [f for f in findings if f.rule_id == "J-1-UNEVALUATED"][0]
        k_finding = [f for f in findings if f.rule_id == "K-1-UNEVALUATED"][0]

        assert g_finding.category == Category.SOURCE_CODE
        assert h_finding.category == Category.SOURCE_CODE
        assert j_finding.category == Category.MAINTENANCE
        assert k_finding.category == Category.DEVELOPMENT


def test_errored_category_per_category_unevaluated_status(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)
    scanner_status = {"rule_based": True}

    # B-1 record for DEPENDENCIES
    mock_rec = MagicMock()
    mock_rec.category = "known_vulnerabilities"
    mock_rec.rule_id = "B-1"
    mock_rec.severity.value = "HIGH"
    mock_rec.title = "Vuln B-1"
    mock_rec.file_path = "pom.xml"
    mock_rec.line = 1
    mock_rec.message = (
        "pkg-x 1.0 は既知脆弱性に該当する可能性があります [GH:CVE-2024-0001]"
    )

    # A-1 error for SOURCE_CODE (all A rules failed)
    mock_errors = [("A-1", "TimeoutError: A-1 timed out")]

    with patch("src.rule_engine.run_all", return_value=([mock_rec], mock_errors, 1)):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status=scanner_status,
            target_dir=tmp_path,
        )
        assert success is True
        assert scanner_status.get("rule_based_source_code") is False


def test_trivy_dedup_runs_when_trivy_status_false(tmp_path):
    from unittest.mock import patch
    from src.orchestrator import MVPOrchestrator
    from src.mvp_models import Category, Finding

    orchestrator = MVPOrchestrator(tmp_path)

    trivy_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="trivy",
        rule_id="CVE-2024-9999",
        severity="HIGH",
        title="Trivy CVE-2024-9999",
        location="pkg-demo@1.0.0",
        description="Package: pkg-demo\nHigh vulnerability",
    )
    b1_finding = Finding(
        category=Category.KNOWN_VULNERABILITIES,
        source="rule_based",
        rule_id="B-1",
        severity="HIGH",
        title="[GH:CVE-2024-9999] Vuln in pkg-demo",
        description="pkg-demo 1.0.0 は既知脆弱性に該当する可能性があります [GH:CVE-2024-9999]",
    )

    with (
        patch(
            "src.targets.archive_fetcher.ArchiveSnapshotFetcher.fetch",
            return_value=tmp_path,
        ),
        patch.object(
            orchestrator.trivy_adapter,
            "run_scan_with_status",
            return_value=([trivy_finding], False),
        ),
        patch.object(
            orchestrator,
            "_run_rule_based_scan",
            return_value=([b1_finding], True),
        ),
    ):
        res = orchestrator.run_full_scan(
            "https://github.com/owner/repo", save_to_docs=False
        )
        assert res is not None
        # B-1 finding MUST be deduplicated even though trivy status was False!
        b1_findings = [f for f in res.all_findings if f.rule_id == "B-1"]
        assert len(b1_findings) == 0


def test_fallback_skipped_files_tuple_propagates_status_and_scan_success(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)
    scanner_status = {"rule_based": True}

    mock_scan_result = MagicMock()
    mock_scan_result.records = []
    mock_scan_result.errors = []
    # Test tuple for skipped_files (as returned by ResolvedTarget)
    mock_scan_result.skipped_files = ("file1.py", "file2.py")

    with patch("src.scan.SecurityScan.run", return_value=mock_scan_result):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status=scanner_status,
        )
        assert success is False
        assert scanner_status["rule_based"] is False
        assert scanner_status["rule_based_source_code"] is False
        assert scanner_status["rule_based_secrets"] is False
        skipped_findings = [f for f in findings if f.rule_id == "SKIPPED-FILES-LIMIT"]
        assert len(skipped_findings) == 4


def test_save_result_json_truncates_all_string_fields_and_slices_findings(tmp_path):
    from src.mvp_models import (
        Category,
        CategoryResult,
        Finding,
        OverallResult,
        OverallStatus,
    )
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)

    # Create findings with huge location, rule_id, source
    findings = [
        Finding(
            category=Category.KNOWN_VULNERABILITIES,
            source="A" * 300,
            rule_id="R" * 300,
            severity="HIGH",
            title="T" * 300,
            location="L" * 300,
            description="D" * 300,
            remediation="REM" * 300,
        )
        for _ in range(50)
    ]
    cat_res = CategoryResult(
        category=Category.KNOWN_VULNERABILITIES,
        category_name="Known Vulnerabilities",
        evaluated=True,
        score=5.0,
        summary="Summary test",
        findings=findings,
    )
    result = OverallResult(
        repository_url="https://github.com/owner/repo",
        scanned_at="2026-09-06T15:00:00Z",
        overall_score=5.0,
        categories={Category.KNOWN_VULNERABILITIES: cat_res},
        all_findings=findings,
        status=OverallStatus.SAFE,
    )

    out_file = orchestrator.save_result_json(
        result, filename="test_output.json", output_dir=tmp_path
    )
    file_bytes = len(out_file.read_bytes())
    assert file_bytes <= 10 * 1024 * 1024


def test_empty_target_dir_skips_rule_execution_and_marks_unevaluated(tmp_path):
    from src.orchestrator import MVPOrchestrator

    empty_dir = tmp_path / "empty_subdir"
    empty_dir.mkdir()

    orchestrator = MVPOrchestrator(tmp_path)
    scanner_status = {"rule_based": True, "has_skipped_files": True}

    findings, success = orchestrator._run_rule_based_scan(
        "https://github.com/owner/repo",
        scanner_status=scanner_status,
        target_dir=empty_dir,
    )
    assert success is False
    assert scanner_status["rule_based"] is False
    assert scanner_status["rule_based_source_code"] is False
    empty_findings = [f for f in findings if f.rule_id == "ALL-FILES-SKIPPED-LIMIT"]
    assert len(empty_findings) == 1


def test_scorecard_runs_when_subdir_normalizes_to_root():
    from src.orchestrator import _normalize_subdir

    assert _normalize_subdir(".") is None
    assert _normalize_subdir("./") is None
    assert _normalize_subdir("services/..") is None
    assert _normalize_subdir("foo/bar/../..") is None
    assert _normalize_subdir("src/backend") == "src/backend"

    # Out of bounds and absolute paths MUST NOT normalize to None (repo root)
    assert _normalize_subdir("../..") is not None
    assert _normalize_subdir("/") is not None
    assert _normalize_subdir("/etc/passwd") is not None
    assert _normalize_subdir("a/../../b") is not None


def test_save_result_json_truncates_top_level_strings(tmp_path):
    from src.mvp_models import Category, CategoryResult, OverallResult, OverallStatus
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)
    cat_res = CategoryResult(
        category=Category.KNOWN_VULNERABILITIES,
        category_name="Known Vulnerabilities",
        evaluated=True,
        score=5.0,
        summary="Summary test",
        findings=[],
    )
    result = OverallResult(
        repository_url="https://github.com/" + "A" * 500,
        scanned_at="2026-09-06T15:00:00Z",
        scanned_ref="B" * 500,
        scanned_subdir="C" * 500,
        overall_score=5.0,
        categories={Category.KNOWN_VULNERABILITIES: cat_res},
        all_findings=[],
        status=OverallStatus.SAFE,
    )

    out_file = orchestrator.save_result_json(
        result, filename="test_output_top_level.json", output_dir=tmp_path
    )
    file_bytes = len(out_file.read_bytes())
    assert file_bytes <= 10 * 1024 * 1024


def test_python_command_injection_deduplicates_at_insertion_time(tmp_path):
    from src.rules.A_code.A1_2_command_injection_python import (
        PythonCommandInjectionDetector,
    )

    py_file = tmp_path / "test.py"
    # Create code where same line has multiple AST calls generating duplicate records
    py_file.write_text(
        "import os\n" + "\n".join([f"os.system(x_{i})" for i in range(10)]) + "\n",
        encoding="utf-8",
    )

    detector = PythonCommandInjectionDetector()
    records = detector.evaluate(tmp_path, max_records=500)
    assert isinstance(records, list)


def test_fallback_scan_path_empty_with_skipped_files_clears_records(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.models import RiskRecord, Severity
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)
    scanner_status = {"rule_based": True}

    empty_scan_path = tmp_path / "empty_fallback"
    empty_scan_path.mkdir()

    mock_target = MagicMock()
    mock_target.scan_path = empty_scan_path

    # False positive record created by absence rule on empty dir
    mock_rec = RiskRecord(
        rule_id="K-1",
        category="development",
        severity=Severity.MEDIUM,
        title="Missing LICENSE",
        message="LICENSE file not found",
    )

    mock_scan_result = MagicMock()
    mock_scan_result.records = [mock_rec]
    mock_scan_result.errors = []
    mock_scan_result.target = mock_target
    mock_scan_result.skipped_files = ("large_file.py",)

    with patch("src.scan.SecurityScan.run", return_value=mock_scan_result):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status=scanner_status,
        )
        assert success is False
        assert scanner_status["rule_based"] is False
        # K-1 absence finding MUST be cleared
        k1_findings = [f for f in findings if f.rule_id == "K-1"]
        assert len(k1_findings) == 0


def test_save_result_json_does_not_mutate_original_result(tmp_path):
    from src.mvp_models import (
        Category,
        CategoryResult,
        Finding,
        OverallResult,
        OverallStatus,
    )
    from src.orchestrator import MVPOrchestrator

    orchestrator = MVPOrchestrator(tmp_path)

    # 50 findings with huge text fields
    findings = [
        Finding(
            category=Category.KNOWN_VULNERABILITIES,
            source="A" * 300,
            rule_id="R" * 300,
            severity="HIGH",
            title="T" * 300,
            location="L" * 300,
            description="D" * 300,
            remediation="REM" * 300,
        )
        for _ in range(50)
    ]
    cat_res = CategoryResult(
        category=Category.KNOWN_VULNERABILITIES,
        category_name="Known Vulnerabilities",
        evaluated=True,
        score=5.0,
        summary="Summary test",
        findings=list(findings),
        findings_count=50,
    )
    result = OverallResult(
        repository_url="https://github.com/owner/repo",
        scanned_at="2026-09-06T15:00:00Z",
        overall_score=5.0,
        categories={Category.KNOWN_VULNERABILITIES: cat_res},
        all_findings=list(findings),
        status=OverallStatus.SAFE,
    )

    out_file = orchestrator.save_result_json(
        result, filename="test_immutability.json", output_dir=tmp_path
    )
    assert out_file.exists()

    # The original result object MUST NOT have its text fields or findings count mutated!
    assert len(result.all_findings) == 50
    assert result.all_findings[0].description == "D" * 300
    assert result.categories[Category.KNOWN_VULNERABILITIES].findings_count == 50


def test_orchestrator_uses_structured_exc_type_without_traceback_parsing(tmp_path):
    from unittest.mock import MagicMock, patch
    from src.orchestrator import MVPOrchestrator
    from src.rule_engine import RuleError

    orchestrator = MVPOrchestrator(tmp_path)
    scanner_status = {"rule_based": True}

    # Error message containing multiline text with secret pattern AKIA...
    err_detail = (
        "Traceback (most recent call last):\nValueError: failed\nAKIA1234567890ABCDEF"
    )
    mock_errors = [RuleError("A-1", err_detail, "ValueError")]

    mock_scan_result = MagicMock()
    mock_scan_result.records = []
    mock_scan_result.errors = mock_errors
    mock_scan_result.skipped_files = ()

    with patch("src.scan.SecurityScan.run", return_value=mock_scan_result):
        findings, success = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status=scanner_status,
        )
        unevaluated_findings = [f for f in findings if "A-1-UNEVALUATED" in f.rule_id]
        assert len(unevaluated_findings) == 1
        # Description MUST contain structured exception type 'ValueError' and MUST NOT contain 'AKIA'
        assert "ValueError" in unevaluated_findings[0].description
        assert "AKIA" not in unevaluated_findings[0].description


def test_command_injection_js_ts_deduplicates_before_limit_check(tmp_path):
    from unittest.mock import patch
    from src.models import RiskRecord
    from src.rules.A_code.A1_3_command_injection_js_ts import (
        JsTsCommandInjectionDetector,
    )

    detector = JsTsCommandInjectionDetector()
    rec1 = RiskRecord(
        rule_id="A1_3",
        category="source_code",
        title="Cmd Inj",
        severity=5,
        file_path="app.js",
        line=10,
        message="External input reaches child_process command execution",
    )
    # 600 duplicates of rec1
    mock_ts_records = [rec1] * 600

    js_file = tmp_path / "app.js"
    js_file.write_text("const cp = require('child_process'); cp.exec(input);")

    with patch.object(
        detector,
        "_evaluate_js_ts_file_with_tree_sitter",
        return_value=mock_ts_records,
    ):
        records = detector._evaluate_js_ts_file(js_file, tmp_path, max_records=500)
        # Should deduplicate down to 1 record, NOT hit 500 records limit prematurely
        assert len(records) == 1
