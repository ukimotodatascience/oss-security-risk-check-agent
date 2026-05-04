from src.config import ConfigOverrides, ScanConfig


def test_cli_url_override_takes_precedence_over_env_target_dir(tmp_path, monkeypatch):
    local_target = tmp_path / "local"
    local_target.mkdir()
    monkeypatch.setenv("TARGET_DIR", str(local_target))

    config = ScanConfig(
        tmp_path,
        ConfigOverrides(
            target_url="https://github.com/owner/repo",
            target_ref="main",
            target_subdir="backend",
        ),
    )

    spec = config.resolve_target_spec()

    assert spec.source_type == "remote_archive"
    assert spec.repo_url == "https://github.com/owner/repo"
    assert spec.ref == "main"
    assert spec.subdir == "backend"


def test_cli_output_dir_override_takes_precedence_over_env(tmp_path, monkeypatch):
    env_output = tmp_path / "env-output"
    cli_output = tmp_path / "cli-output"
    monkeypatch.setenv("OUTPUT_DIR", str(env_output))

    config = ScanConfig(
        tmp_path,
        ConfigOverrides(output_dir=str(cli_output)),
    )

    assert config.resolve_output_dir() == cli_output.resolve()


def test_env_target_dir_still_works_without_cli_override(tmp_path, monkeypatch):
    local_target = tmp_path / "local"
    local_target.mkdir()
    monkeypatch.setenv("TARGET_DIR", str(local_target))
    monkeypatch.delenv("TARGET_REPO_URL", raising=False)

    config = ScanConfig(tmp_path)

    spec = config.resolve_target_spec()

    assert spec.source_type == "local"
    assert spec.local_dir == local_target.resolve()
