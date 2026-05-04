from pathlib import Path

from src.targets.models import ScanTargetSpec
from src.targets.resolver import TargetResolver


class FakeFetcher:
    def __init__(self) -> None:
        self.work_dir: Path | None = None

    def fetch(self, spec: ScanTargetSpec, work_dir: Path) -> Path:
        self.work_dir = work_dir
        repo = work_dir / "repo"
        repo.mkdir()
        (repo / "README.md").write_text("hello", encoding="utf-8")
        return repo


def test_target_resolver_returns_local_path(tmp_path):
    resolver = TargetResolver(FakeFetcher())
    spec = ScanTargetSpec(source_type="local", local_dir=tmp_path)

    with resolver.resolve(spec) as resolved:
        assert resolved.scan_path == tmp_path
        assert resolved.fetch_mode == "local"


def test_target_resolver_fetches_remote_archive_and_cleans_up():
    fetcher = FakeFetcher()
    resolver = TargetResolver(fetcher)
    spec = ScanTargetSpec(
        source_type="remote_archive",
        repo_url="https://github.com/owner/repo",
        ref="main",
    )

    with resolver.resolve(spec) as resolved:
        assert resolved.scan_path.exists()
        assert (resolved.scan_path / "README.md").exists()
        assert resolved.fetch_mode == "github_archive_zipball"
        work_dir = fetcher.work_dir

    assert work_dir is not None
    assert not work_dir.exists()
