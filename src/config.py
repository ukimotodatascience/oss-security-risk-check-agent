from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


class ScanConfig:
    """`.env` と環境変数から診断対象パス・レポート出力先を解決する。"""

    def __init__(self, project_root: Path) -> None:
        self._project_root = project_root
        load_dotenv(self._project_root / ".env")

    def resolve_target_dir(self) -> Path:
        """`TARGET_DIR` を読み、存在するディレクトリの絶対パスを返す。"""
        raw = os.environ.get("TARGET_DIR", "").strip().strip('"').strip("'")
        if not raw:
            raise SystemExit(
                "TARGET_DIR が設定されていません。.env.example を .env にコピーし、"
                "TARGET_DIR に診断対象のディレクトリパスを設定してください。"
            )
        target = Path(raw).expanduser().resolve()
        if not target.is_dir():
            raise SystemExit(
                f"TARGET_DIR が存在しないかディレクトリではありません: {target}"
            )
        return target

    def resolve_output_dir(self) -> Path:
        """`OUTPUT_DIR` を読み、レポート保存用ディレクトリの絶対パスを返す。

        未設定のときはプロジェクト直下の `.reports` を使う。
        """
        raw = os.environ.get("OUTPUT_DIR", "").strip().strip('"').strip("'")
        if not raw:
            out = self._project_root / ".reports"
        else:
            out = Path(raw).expanduser().resolve()
        if out.exists() and not out.is_dir():
            raise SystemExit(f"OUTPUT_DIR はディレクトリである必要があります: {out}")
        out.mkdir(parents=True, exist_ok=True)
        return out
