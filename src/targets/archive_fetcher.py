from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

from src.targets.models import ScanTargetSpec
from src.targets.safe_extract import safe_extract_zip
from src.targets.url_validator import parse_github_repo_url


class ArchiveSnapshotFetcher:
    """Git コマンドを使わず GitHub archive snapshot を取得する。"""

    USER_AGENT = "oss-security-risk-check-agent"

    def __init__(
        self,
        *,
        max_download_bytes: int,
        max_extracted_bytes: int,
        max_files: int,
        max_single_file_bytes: int,
        timeout_sec: int,
    ) -> None:
        self._max_download_bytes = max_download_bytes
        self._max_extracted_bytes = max_extracted_bytes
        self._max_files = max_files
        self._max_single_file_bytes = max_single_file_bytes
        self._timeout_sec = timeout_sec

    def fetch(self, spec: ScanTargetSpec, work_dir: Path) -> Path:
        """remote archive target を一時作業ディレクトリへ取得・展開する。"""

        if not spec.repo_url:
            raise ValueError("TARGET_REPO_URL が指定されていません。")

        repo = parse_github_repo_url(spec.repo_url)
        ref = spec.ref or "HEAD"
        archive_url = (
            f"https://api.github.com/repos/{repo.owner}/{repo.repo}/zipball/{ref}"
        )

        work_dir.mkdir(parents=True, exist_ok=True)
        archive_path = work_dir / "source.zip"
        self._download_limited(archive_url, archive_path)

        extracted_root = safe_extract_zip(
            archive_path,
            work_dir / "source",
            max_files=self._max_files,
            max_total_size=self._max_extracted_bytes,
            max_single_file_size=self._max_single_file_bytes,
        )

        if spec.subdir:
            subdir = (extracted_root / spec.subdir).resolve()
            root = extracted_root.resolve()
            if root != subdir and root not in subdir.parents:
                raise ValueError("TARGET_SUBDIR が展開ルート外を指しています。")
            if not subdir.is_dir():
                raise ValueError(f"TARGET_SUBDIR が存在しません: {spec.subdir}")
            return subdir

        return extracted_root

    def _download_limited(self, url: str, dest: Path) -> None:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": self.USER_AGENT},
            method="GET",
        )

        downloaded = 0
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_sec) as response:
                with dest.open("wb") as fh:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        downloaded += len(chunk)
                        if downloaded > self._max_download_bytes:
                            raise ValueError(
                                "archive ダウンロードサイズが上限を超えました。"
                            )
                        fh.write(chunk)
        except urllib.error.URLError as exc:
            raise ValueError(f"archive の取得に失敗しました: {exc}") from exc
