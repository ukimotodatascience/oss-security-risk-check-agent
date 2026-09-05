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
