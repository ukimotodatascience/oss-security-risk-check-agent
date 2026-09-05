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
        assert cmd[4] == "/tmp/some_repo"

        # Test URL triggers "repo" mode
        adapter.run_scan("https://github.com/owner/repo")
        cmd2 = mock_popen.call_args[0][0]
        assert cmd2[1] == "repo"
        assert cmd2[4] == "https://github.com/owner/repo"


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

        # When trivy scanner is True (succeeded), secrets rule-based finding is skipped (handled by Trivy)
        findings_trivy_ok, _ = orchestrator._run_rule_based_scan(
            "https://github.com/owner/repo",
            scanner_status={"trivy": True},
        )
        assert len(findings_trivy_ok) == 0


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
        assert cat_map["MAINT-001"] == Category.MAINTENANCE
