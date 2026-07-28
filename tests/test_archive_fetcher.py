from __future__ import annotations

import io
import urllib.error
import zipfile

import pytest

from src.targets.archive_fetcher import ArchiveSnapshotFetcher
from src.targets.models import ScanTargetSpec


class FakeResponse:
    def __init__(self, payload: bytes, chunk_size: int | None = None) -> None:
        self._payload = payload
        self._offset = 0
        self._chunk_size = chunk_size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._payload):
            return b""
        effective_size = self._chunk_size or size
        if effective_size < 0:
            effective_size = len(self._payload) - self._offset
        chunk = self._payload[self._offset : self._offset + effective_size]
        self._offset += len(chunk)
        return chunk


def build_zip(entries: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def make_fetcher(max_download_bytes: int = 1024 * 1024) -> ArchiveSnapshotFetcher:
    return ArchiveSnapshotFetcher(
        max_download_bytes=max_download_bytes,
        max_extracted_bytes=1024 * 1024,
        max_files=20,
        max_single_file_bytes=1024,
        timeout_sec=7,
    )


def test_archive_fetcher_downloads_github_zipball_and_returns_extracted_root(
    tmp_path, monkeypatch
):
    from src.targets import archive_fetcher as archive_module

    payload = build_zip({"repo-main/README.md": "hello"})
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["user_agent"] = request.headers["User-agent"]
        captured["timeout"] = timeout
        return FakeResponse(payload)

    monkeypatch.setattr(archive_module.urllib.request, "urlopen", fake_urlopen)

    spec = ScanTargetSpec(
        source_type="remote_archive",
        repo_url="https://github.com/owner/repo",
        ref="main",
    )

    extracted = make_fetcher().fetch(spec, tmp_path)

    assert captured == {
        "url": "https://api.github.com/repos/owner/repo/zipball/main",
        "user_agent": "oss-security-risk-check-agent",
        "timeout": 7,
    }
    assert extracted == tmp_path / "source" / "repo-main"
    assert (extracted / "README.md").read_text(encoding="utf-8") == "hello"


def test_archive_fetcher_uses_head_when_ref_is_not_specified(tmp_path, monkeypatch):
    from src.targets import archive_fetcher as archive_module

    payload = build_zip({"repo-head/file.txt": "content"})
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        return FakeResponse(payload)

    monkeypatch.setattr(archive_module.urllib.request, "urlopen", fake_urlopen)

    spec = ScanTargetSpec(
        source_type="remote_archive",
        repo_url="https://github.com/owner/repo",
    )

    extracted = make_fetcher().fetch(spec, tmp_path)

    assert captured["url"].endswith("/zipball/HEAD")
    assert (extracted / "file.txt").exists()


def test_archive_fetcher_returns_requested_safe_subdir(tmp_path, monkeypatch):
    from src.targets import archive_fetcher as archive_module

    payload = build_zip({"repo-main/backend/app.py": "print('ok')"})
    monkeypatch.setattr(
        archive_module.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse(payload),
    )

    spec = ScanTargetSpec(
        source_type="remote_archive",
        repo_url="https://github.com/owner/repo",
        ref="main",
        subdir="backend",
    )

    extracted = make_fetcher().fetch(spec, tmp_path)

    assert extracted.name == "backend"
    assert (extracted / "app.py").exists()


def test_archive_fetcher_rejects_missing_repo_url(tmp_path):
    spec = ScanTargetSpec(source_type="remote_archive")

    with pytest.raises(ValueError, match="TARGET_REPO_URL"):
        make_fetcher().fetch(spec, tmp_path)


def test_archive_fetcher_rejects_missing_subdir(tmp_path, monkeypatch):
    from src.targets import archive_fetcher as archive_module

    payload = build_zip({"repo-main/README.md": "hello"})
    monkeypatch.setattr(
        archive_module.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse(payload),
    )
    spec = ScanTargetSpec(
        source_type="remote_archive",
        repo_url="https://github.com/owner/repo",
        subdir="missing",
    )

    with pytest.raises(ValueError, match="TARGET_SUBDIR が存在しません"):
        make_fetcher().fetch(spec, tmp_path)


def test_archive_fetcher_rejects_subdir_escape(tmp_path, monkeypatch):
    from src.targets import archive_fetcher as archive_module

    payload = build_zip({"repo-main/README.md": "hello"})
    monkeypatch.setattr(
        archive_module.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse(payload),
    )
    spec = ScanTargetSpec(
        source_type="remote_archive",
        repo_url="https://github.com/owner/repo",
        subdir="..",
    )

    with pytest.raises(ValueError, match="TARGET_SUBDIR が展開ルート外"):
        make_fetcher().fetch(spec, tmp_path)


def test_archive_fetcher_rejects_download_larger_than_limit(tmp_path, monkeypatch):
    from src.targets import archive_fetcher as archive_module

    monkeypatch.setattr(
        archive_module.urllib.request,
        "urlopen",
        lambda request, timeout: FakeResponse(b"abcdef", chunk_size=3),
    )

    with pytest.raises(ValueError, match="ダウンロードサイズが上限"):
        make_fetcher(max_download_bytes=5)._download_limited(
            "https://example.com/source.zip", tmp_path / "source.zip"
        )


def test_archive_fetcher_wraps_url_errors(tmp_path, monkeypatch):
    from src.targets import archive_fetcher as archive_module

    def fake_urlopen(request, timeout):
        raise urllib.error.URLError("timeout")

    monkeypatch.setattr(archive_module.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ValueError, match="archive の取得に失敗しました"):
        make_fetcher()._download_limited(
            "https://example.com/source.zip", tmp_path / "source.zip"
        )


def test_archive_fetcher_includes_auth_header_when_token_provided(
    tmp_path, monkeypatch
):
    from src.targets import archive_fetcher as archive_module

    payload = build_zip({"repo-main/README.md": "hello"})
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["user_agent"] = request.headers["User-agent"]
        captured["auth"] = request.headers.get("Authorization")
        captured["timeout"] = timeout
        return FakeResponse(payload)

    monkeypatch.setattr(archive_module.urllib.request, "urlopen", fake_urlopen)

    spec = ScanTargetSpec(
        source_type="remote_archive",
        repo_url="https://github.com/owner/repo",
        ref="main",
    )

    fetcher = ArchiveSnapshotFetcher(
        max_download_bytes=1024 * 1024,
        max_extracted_bytes=1024 * 1024,
        max_files=20,
        max_single_file_bytes=1024,
        timeout_sec=7,
        github_token="secret_token",
    )
    fetcher.fetch(spec, tmp_path)

    assert captured == {
        "url": "https://api.github.com/repos/owner/repo/zipball/main",
        "user_agent": "oss-security-risk-check-agent",
        "auth": "Bearer secret_token",
        "timeout": 7,
    }
