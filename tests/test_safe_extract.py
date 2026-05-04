import stat
import zipfile

import pytest

from src.targets.safe_extract import ArchiveSafetyError, safe_extract_zip


def test_safe_extract_zip_extracts_normal_archive(tmp_path):
    zip_path = tmp_path / "source.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("repo/README.md", "hello")

    root = safe_extract_zip(
        zip_path,
        tmp_path / "out",
        max_files=10,
        max_total_size=1000,
        max_single_file_size=1000,
    )

    assert root.name == "repo"
    assert (root / "README.md").read_text(encoding="utf-8") == "hello"


def test_safe_extract_zip_rejects_zip_slip(tmp_path):
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.py", "print('evil')")

    with pytest.raises(ArchiveSafetyError):
        safe_extract_zip(
            zip_path,
            tmp_path / "out",
            max_files=10,
            max_total_size=1000,
            max_single_file_size=1000,
        )


def test_safe_extract_zip_rejects_symlink_entries(tmp_path):
    zip_path = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("repo/link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(info, "target")

    with pytest.raises(ArchiveSafetyError):
        safe_extract_zip(
            zip_path,
            tmp_path / "out",
            max_files=10,
            max_total_size=1000,
            max_single_file_size=1000,
        )


def test_safe_extract_zip_rejects_file_count_limit(tmp_path):
    zip_path = tmp_path / "many.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("repo/a.txt", "a")
        zf.writestr("repo/b.txt", "b")

    with pytest.raises(ArchiveSafetyError):
        safe_extract_zip(
            zip_path,
            tmp_path / "out",
            max_files=1,
            max_total_size=1000,
            max_single_file_size=1000,
        )


def test_safe_extract_zip_rejects_size_limit(tmp_path):
    zip_path = tmp_path / "large.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("repo/large.txt", "x" * 20)

    with pytest.raises(ArchiveSafetyError):
        safe_extract_zip(
            zip_path,
            tmp_path / "out",
            max_files=10,
            max_total_size=10,
            max_single_file_size=1000,
        )
