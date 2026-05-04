from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from src.targets.models import RemoteFetchLimits, ScanTargetSpec


@dataclass(frozen=True)
class ConfigOverrides:
    """CLI など `.env` より優先したい設定値。"""

    target_url: str | None = None
    target_ref: str | None = None
    target_subdir: str | None = None
    output_dir: str | None = None


class ScanConfig:
    """`.env` と環境変数から診断対象パス・レポート出力先を解決する。"""

    _BYTES_PER_MB = 1024 * 1024

    def __init__(
        self,
        project_root: Path,
        overrides: ConfigOverrides | None = None,
    ) -> None:
        self._project_root = project_root
        self._overrides = overrides or ConfigOverrides()
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

    def resolve_target_spec(self) -> ScanTargetSpec:
        """ローカル/URL 指定を `ScanTargetSpec` として解決する。"""
        raw_dir = self._env("TARGET_DIR")
        raw_url = self._overrides.target_url or self._env("TARGET_REPO_URL")
        ref = self._overrides.target_ref or self._env("TARGET_REF") or None
        subdir = self._overrides.target_subdir or self._env("TARGET_SUBDIR") or None

        if self._overrides.target_url:
            return ScanTargetSpec(
                source_type="remote_archive",
                repo_url=raw_url,
                ref=ref,
                subdir=subdir,
            )

        if raw_dir and raw_url:
            raise SystemExit("TARGET_DIR と TARGET_REPO_URL は同時に指定できません。")
        if not raw_dir and not raw_url:
            raise SystemExit(
                "TARGET_DIR または TARGET_REPO_URL のどちらかを設定してください。"
            )

        if raw_dir:
            target = Path(raw_dir).expanduser().resolve()
            if not target.is_dir():
                raise SystemExit(
                    f"TARGET_DIR が存在しないかディレクトリではありません: {target}"
                )
            return ScanTargetSpec(source_type="local", local_dir=target)

        return ScanTargetSpec(
            source_type="remote_archive",
            repo_url=raw_url,
            ref=ref,
            subdir=subdir,
        )

    def resolve_remote_fetch_limits(self) -> RemoteFetchLimits:
        """remote archive の取得・展開に使う安全上限を解決する。"""
        return RemoteFetchLimits(
            timeout_sec=self._env_int("TARGET_FETCH_TIMEOUT_SEC", 60),
            max_download_bytes=self._env_mb("TARGET_MAX_DOWNLOAD_MB", 100),
            max_extracted_bytes=self._env_mb("TARGET_MAX_EXTRACTED_MB", 300),
            max_files=self._env_int("TARGET_MAX_FILES", 30000),
            max_single_file_bytes=self._env_mb("TARGET_MAX_SINGLE_FILE_MB", 10),
        )

    def resolve_output_dir(self) -> Path:
        """`OUTPUT_DIR` を読み、レポート保存用ディレクトリの絶対パスを返す。

        未設定のときはプロジェクト直下の `.reports` を使う。
        """
        raw = self._overrides.output_dir or self._env("OUTPUT_DIR")
        if not raw:
            out = self._project_root / ".reports"
        else:
            out = Path(raw).expanduser().resolve()
        if out.exists() and not out.is_dir():
            raise SystemExit(f"OUTPUT_DIR はディレクトリである必要があります: {out}")
        out.mkdir(parents=True, exist_ok=True)
        return out

    @staticmethod
    def _env(name: str) -> str:
        return os.environ.get(name, "").strip().strip('"').strip("'")

    @classmethod
    def _env_int(cls, name: str, default: int) -> int:
        raw = cls._env(name)
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError as exc:
            raise SystemExit(f"{name} は整数で指定してください: {raw}") from exc
        if value <= 0:
            raise SystemExit(f"{name} は 1 以上で指定してください: {raw}")
        return value

    @classmethod
    def _env_mb(cls, name: str, default_mb: int) -> int:
        return cls._env_int(name, default_mb) * cls._BYTES_PER_MB
