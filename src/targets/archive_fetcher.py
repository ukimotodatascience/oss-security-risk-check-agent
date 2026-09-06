from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


from src.targets.models import ScanTargetSpec, SkippedFile
from src.targets.safe_extract import safe_extract_zip
from src.targets.url_validator import parse_github_repo_url


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """リダイレクト時にホスト名が異なる場合、Authorization ヘッダーを削除するハンドラー。"""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None

        orig_parsed = urllib.parse.urlparse(req.full_url)
        new_parsed = urllib.parse.urlparse(new_req.full_url)

        if orig_parsed.netloc != new_parsed.netloc:
            new_req.remove_header("Authorization")

        return new_req


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
        github_token: str | None = None,
    ) -> None:
        self._max_download_bytes = max_download_bytes
        self._max_extracted_bytes = max_extracted_bytes
        self._max_files = max_files
        self._max_single_file_bytes = max_single_file_bytes
        self._timeout_sec = timeout_sec
        self._github_token = github_token
        self.skipped_files: tuple[SkippedFile, ...] = ()

    def fetch(self, spec: ScanTargetSpec, work_dir: Path) -> Path:
        """remote archive target を一時作業ディレクトリへ取得・展開する。"""

        self.skipped_files = ()

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

        extracted_root, skipped_files = safe_extract_zip(
            archive_path,
            work_dir / "source",
            max_files=self._max_files,
            max_total_size=self._max_extracted_bytes,
            max_single_file_size=self._max_single_file_bytes,
        )
        self.skipped_files = skipped_files

        if spec.subdir:
            subdir = (extracted_root / spec.subdir).resolve()
            root = extracted_root.resolve()
            if root != subdir and root not in subdir.parents:
                raise ValueError("TARGET_SUBDIR が展開ルート外を指しています。")
            if not subdir.is_dir():
                # もし全ファイルがサイズ上限等で省略されていた場合、空ディレクトリを作成して正常返却
                if self.skipped_files and any(
                    self._is_in_subdir(sf, spec.subdir) for sf in self.skipped_files
                ):
                    subdir.mkdir(parents=True, exist_ok=True)
                    return subdir
                raise ValueError(f"TARGET_SUBDIR が存在しません: {spec.subdir}")
            return subdir

        return extracted_root

    @staticmethod
    def _is_in_subdir(item: Any, subdir: str) -> bool:
        raw_path = item.path if hasattr(item, "path") else str(item)
        parts = [p for p in raw_path.replace("\\", "/").split("/") if p and p != "."]
        norm_parts: list[str] = []
        for pt in parts:
            if pt == "..":
                if norm_parts:
                    norm_parts.pop()
            else:
                norm_parts.append(pt)
        norm_item = "/".join(norm_parts)

        sub_parts = [p for p in subdir.replace("\\", "/").split("/") if p and p != "."]
        norm_sub = "/".join(sub_parts)
        if not norm_sub:
            return True

        item_parts = [p for p in norm_item.split("/") if p]
        if not item_parts:
            return False

        rel_path = "/".join(item_parts[1:]) if len(item_parts) > 1 else ""
        if rel_path:
            if rel_path == norm_sub or rel_path.startswith(norm_sub + "/"):
                return True

        raw_path_str = "/".join(item_parts)
        if raw_path_str == norm_sub or raw_path_str.startswith(norm_sub + "/"):
            return True

        return False

    def _download_limited(self, url: str, dest: Path) -> None:
        headers = {"User-Agent": self.USER_AGENT}
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"
        request = urllib.request.Request(
            url,
            headers=headers,
            method="GET",
        )

        downloaded = 0
        opener = urllib.request.build_opener(SafeRedirectHandler())
        try:
            with opener.open(request, timeout=self._timeout_sec) as response:
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
