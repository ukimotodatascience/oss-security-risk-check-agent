from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from src.targets.models import SkippedFile


class ArchiveSafetyError(Exception):
    """安全でない archive を検出したときの例外。"""


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return stat.S_ISLNK(mode)


def _safe_member_path(name: str) -> PurePosixPath:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise ArchiveSafetyError(f"絶対パスを含む archive は拒否します: {name}")
    if ".." in path.parts:
        raise ArchiveSafetyError(
            f"親ディレクトリ参照を含む archive は拒否します: {name}"
        )
    if not path.parts:
        raise ArchiveSafetyError(f"不正な archive entry です: {name}")
    return path


def safe_extract_zip(
    zip_path: Path,
    dest_dir: Path,
    *,
    max_files: int,
    max_total_size: int,
    max_single_file_size: int,
) -> tuple[Path, tuple[SkippedFile, ...]]:
    """zip を検証しながら展開し、展開後のルートディレクトリとスキップ情報を返す。"""

    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()
    file_count = 0
    total_size = 0
    top_level_names: set[str] = set()
    skipped_files: list[SkippedFile] = []

    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            if not info.filename or info.filename.endswith("/"):
                continue
            if _is_symlink(info):
                raise ArchiveSafetyError(
                    f"symlink を含む archive は拒否します: {info.filename}"
                )

            member_path = _safe_member_path(info.filename)
            top_level_names.add(member_path.parts[0])
            if info.file_size > max_single_file_size:
                skipped_files.append(
                    SkippedFile(
                        path=info.filename,
                        reason="単一ファイルサイズ上限を超えたためスキップしました。",
                        size_bytes=info.file_size,
                        limit_bytes=max_single_file_size,
                    )
                )
                continue

            file_count += 1
            if file_count > max_files:
                raise ArchiveSafetyError(
                    "archive 内のファイル数が上限を超えています。"
                    f" path={info.filename}, size={info.file_size} bytes, "
                    f"max_files={max_files}"
                )

            total_size += info.file_size
            if total_size > max_total_size:
                raise ArchiveSafetyError("archive 展開後サイズが上限を超えています。")

            target_path = (dest_root / Path(*member_path.parts)).resolve()
            if dest_root != target_path and dest_root not in target_path.parents:
                raise ArchiveSafetyError(
                    f"展開先外への書き込みを検出しました: {info.filename}"
                )

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, target_path.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)

    if len(top_level_names) == 1:
        root = dest_root / next(iter(top_level_names))
        if root.is_dir():
            return root, tuple(skipped_files)
    return dest_root, tuple(skipped_files)
