from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Protocol

from src.targets.models import ResolvedTarget, ScanTargetSpec


class TargetFetcher(Protocol):
    def fetch(self, spec: ScanTargetSpec, work_dir: Path) -> Path: ...


class TargetResolver:
    """ScanTargetSpec を既存ルールが扱える Path に解決する。"""

    def __init__(self, fetcher: TargetFetcher) -> None:
        self._fetcher = fetcher

    @contextmanager
    def resolve(self, spec: ScanTargetSpec) -> Iterator[ResolvedTarget]:
        if spec.source_type == "local":
            if not spec.local_dir or not spec.local_dir.is_dir():
                raise ValueError(
                    "TARGET_DIR が存在しないかディレクトリではありません。"
                )
            yield ResolvedTarget(
                display_name=str(spec.local_dir),
                scan_path=spec.local_dir,
                fetch_mode="local",
            )
            return

        if spec.source_type == "remote_archive":
            work_dir = Path(tempfile.mkdtemp(prefix="oss-risk-scan-"))
            try:
                scan_path = self._fetcher.fetch(spec, work_dir)
                yield ResolvedTarget(
                    display_name=spec.repo_url or str(scan_path),
                    scan_path=scan_path,
                    source_url=spec.repo_url,
                    ref=spec.ref,
                    subdir=spec.subdir,
                    fetch_mode="github_archive_zipball",
                )
            finally:
                shutil.rmtree(work_dir, ignore_errors=True)
            return

        raise ValueError(f"未対応の source_type です: {spec.source_type}")
