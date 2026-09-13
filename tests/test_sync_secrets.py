from __future__ import annotations

import os
from unittest.mock import MagicMock

from app import _sync_secrets_to_env
from src.config import ScanConfig


def test_sync_secrets_to_env_preserves_existing_env(monkeypatch):
    """既存の GITHUB_AUTH_TOKEN が存在する場合、st.secrets で上書き・追加しないことを確認。"""
    monkeypatch.setenv("GITHUB_TOKEN", "  ")
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "existing_auth_token")
    monkeypatch.delenv("GH_TOKEN", raising=False)

    fake_st = MagicMock()
    fake_st.secrets = {"GITHUB_TOKEN": "secret_token_from_st"}
    monkeypatch.setattr("app.st", fake_st)

    _sync_secrets_to_env()

    # 空白のみの GITHUB_TOKEN は無視され、有効な GITHUB_AUTH_TOKEN が優先されて st.secrets で上書きされないこと
    assert os.environ.get("GITHUB_TOKEN") == "  "
    assert os.environ.get("GITHUB_AUTH_TOKEN") == "existing_auth_token"


def test_sync_secrets_to_env_populates_env_when_empty(monkeypatch):
    """環境変数にトークンがない場合、st.secrets の値が os.environ に同期されることを確認。"""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    fake_st = MagicMock()
    fake_st.secrets = {"GITHUB_TOKEN": "new_secret_token"}
    monkeypatch.setattr("app.st", fake_st)

    _sync_secrets_to_env()

    assert os.environ.get("GITHUB_TOKEN") == "new_secret_token"
    assert os.environ.get("GITHUB_AUTH_TOKEN") == "new_secret_token"
    assert os.environ.get("GH_TOKEN") == "new_secret_token"


def test_sync_secrets_to_env_skips_whitespace_secret_candidates(monkeypatch):
    """st.secrets の先頭キーが空白のみの場合、後続の有効なキーから取得できることを確認。"""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    fake_st = MagicMock()
    fake_st.secrets = {
        "GITHUB_TOKEN": "   ",
        "GH_TOKEN": "valid_gh_token",
    }
    monkeypatch.setattr("app.st", fake_st)

    _sync_secrets_to_env()

    assert os.environ.get("GITHUB_TOKEN") == "valid_gh_token"
    assert os.environ.get("GITHUB_AUTH_TOKEN") == "valid_gh_token"
    assert os.environ.get("GH_TOKEN") == "valid_gh_token"


def test_resolve_github_token_reads_env_variables(monkeypatch, tmp_path):
    """ScanConfig.resolve_github_token が正しく環境変数を解決することを確認。"""
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "my_auth_token")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    config = ScanConfig(tmp_path)
    assert config.resolve_github_token() == "my_auth_token"
