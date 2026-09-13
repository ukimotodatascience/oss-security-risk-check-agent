from __future__ import annotations

import io
import tarfile

import app
from app import _install_scanner_binaries


def test_scorecard_extract_matches_scorecard_linux_amd64(tmp_path, monkeypatch):
    """scorecard-linux-amd64 という名称のバイナリが tar 内に含まれている場合、正しく scorecard として解凍配置されるか検証。"""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("app._get_user_bin_dir", lambda: bin_dir)
    monkeypatch.setattr("app.project_root", lambda: tmp_path)

    # 模擬 tar.gz アーカイブ作成
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as tar:
        fake_binary = b"#!/bin/sh\necho scorecard\n"
        info = tarfile.TarInfo(name="scorecard-linux-amd64")
        info.size = len(fake_binary)
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(fake_binary))

    import hashlib

    fake_bin_sha = hashlib.sha256(fake_binary).hexdigest()
    monkeypatch.setitem(app.BINARY_CHECKSUMS["scorecard"], "x86_64", fake_bin_sha)

    mock_data = archive_bytes.getvalue()
    actual_sha = hashlib.sha256(mock_data).hexdigest()
    monkeypatch.setitem(
        app.CHECKSUMS["scorecard"],
        "x86_64",
        (actual_sha, "http://example.com/scorecard.tar.gz"),
    )
    monkeypatch.setattr("app._download_binary_safely", lambda url, **kw: mock_data)
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    monkeypatch.setattr(
        "shutil.which",
        lambda name: str(bin_dir / name) if (bin_dir / name).is_file() else None,
    )

    res = _install_scanner_binaries()

    expected_scorecard = bin_dir / "scorecard"
    assert expected_scorecard.is_file()
    assert res.get("scorecard") is True
