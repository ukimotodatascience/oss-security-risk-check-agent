from __future__ import annotations

import os
from unittest.mock import MagicMock

from app import _sync_secrets_to_env
from src.config import ScanConfig


def test_sync_secrets_to_env_preserves_existing_env(monkeypatch):
    """既存の GITHUB_AUTH_TOKEN が存在する場合、st.secrets で上書き・追加しないことを確認。"""
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "existing_auth_token")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    fake_st = MagicMock()
    fake_st.secrets = {"GITHUB_TOKEN": "secret_token_from_st"}
    monkeypatch.setattr("app.st", fake_st)

    _sync_secrets_to_env()

    # 既存の環境変数が優先され、GITHUB_TOKEN に秘密情報の secret_token_from_st がセットされないこと
    assert os.environ.get("GITHUB_TOKEN") is None
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


def test_resolve_github_token_reads_env_variables(monkeypatch, tmp_path):
    """ScanConfig.resolve_github_token が正しく環境変数を解決することを確認。"""
    monkeypatch.setenv("GITHUB_AUTH_TOKEN", "my_auth_token")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    config = ScanConfig(tmp_path)
    assert config.resolve_github_token() == "my_auth_token"
