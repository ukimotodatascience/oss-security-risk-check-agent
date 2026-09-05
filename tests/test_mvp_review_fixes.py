import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from src.adapters.scorecard_adapter import ScorecardAdapter, CHECK_CATEGORY_MAP
from src.adapters.trivy_adapter import TrivyAdapter
from src.mvp_models import Category, Finding


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
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = '{"Results": []}'
        
        # Test local path triggers "fs" mode
        adapter.run_scan("/tmp/some_repo")
        cmd = mock_run.call_args[0][0]
        assert cmd[1] == "fs"
        assert cmd[4] == "/tmp/some_repo"

        # Test URL triggers "repo" mode
        adapter.run_scan("https://github.com/owner/repo")
        cmd2 = mock_run.call_args[0][0]
        assert cmd2[1] == "repo"
        assert cmd2[4] == "https://github.com/owner/repo"
