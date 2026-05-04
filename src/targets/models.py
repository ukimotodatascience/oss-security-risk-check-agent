from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Optional


@dataclass(frozen=True)
class ScanTargetSpec:
    """ユーザーが指定したスキャン対象。"""

    source_type: Literal["local", "remote_archive"]
    local_dir: Optional[Path] = None
    repo_url: Optional[str] = None
    ref: Optional[str] = None
    subdir: Optional[str] = None


@dataclass(frozen=True)
class RemoteFetchLimits:
    """remote archive 取得・展開時の安全上限。"""

    timeout_sec: int
    max_download_bytes: int
    max_extracted_bytes: int
    max_files: int
    max_single_file_bytes: int


@dataclass(frozen=True)
class ResolvedTarget:
    """ルールエンジンへ渡せる状態に解決済みのスキャン対象。"""

    display_name: str
    scan_path: Path
    source_url: Optional[str] = None
    ref: Optional[str] = None
    subdir: Optional[str] = None
    fetch_mode: str = "local"
