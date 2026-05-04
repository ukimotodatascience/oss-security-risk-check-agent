"""診断の実行フロー（設定読込 → ルール実行 → レポート）。"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from src.config import ConfigOverrides, ScanConfig
from src.reporting import ReportWriter
from src.rule_engine import load_all_rules, run_all
from src.targets.archive_fetcher import ArchiveSnapshotFetcher
from src.targets.resolver import TargetResolver


class CliOptionsLike(Protocol):
    target_url: str | None
    target_ref: str | None
    target_subdir: str | None
    output_dir: str | None


class SecurityScan:
    """ローカルまたは remote archive の対象を診断し、結果を出力する。"""

    def __init__(
        self,
        project_root: Path,
        cli_options: CliOptionsLike | None = None,
    ) -> None:
        self._project_root = project_root
        self._cli_options = cli_options

    def run(self) -> None:
        config = ScanConfig(self._project_root, self._config_overrides())
        target_spec = config.resolve_target_spec()
        output_dir = config.resolve_output_dir()
        limits = config.resolve_remote_fetch_limits()

        fetcher = ArchiveSnapshotFetcher(
            max_download_bytes=limits.max_download_bytes,
            max_extracted_bytes=limits.max_extracted_bytes,
            max_files=limits.max_files,
            max_single_file_bytes=limits.max_single_file_bytes,
            timeout_sec=limits.timeout_sec,
        )
        resolver = TargetResolver(fetcher)

        rules = load_all_rules(self._project_root)
        if not rules:
            raise SystemExit(
                "ルールが 1 つも読み込めませんでした。src/rules の構成を確認してください。"
            )

        generated_at = datetime.now(timezone.utc)
        with resolver.resolve(target_spec) as resolved:
            records, errors, executed_count = run_all(resolved.scan_path, rules)

            report_path = ReportWriter(output_dir).write(
                resolved.scan_path, records, errors, generated_at
            )

            print(f"対象: {resolved.display_name}")
            print(f"スキャンパス: {resolved.scan_path}")
            print(f"取得方式: {resolved.fetch_mode}")
            print(f"出力先: {output_dir}")
            print(f"読み込みルール数: {len(rules)}")
            print(f"実行ルール数: {executed_count}")
            print(f"検知件数: {len(records)}")
            if errors:
                print(f"失敗したルール数: {len(errors)}", file=sys.stderr)
            print(f"レポート: {report_path}")

    def _config_overrides(self) -> ConfigOverrides:
        if self._cli_options is None:
            return ConfigOverrides()
        return ConfigOverrides(
            target_url=self._cli_options.target_url,
            target_ref=self._cli_options.target_ref,
            target_subdir=self._cli_options.target_subdir,
            output_dir=self._cli_options.output_dir,
        )
