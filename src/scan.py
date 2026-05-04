"""診断の実行フロー（設定読込 → ルール実行 → レポート）。"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, Sequence, Tuple

from src.config import ConfigOverrides, ScanConfig
from src.models import RiskRecord
from src.reporting import ReportWriter
from src.rule_engine import load_all_rules, run_all
from src.targets.archive_fetcher import ArchiveSnapshotFetcher
from src.targets.models import ResolvedTarget
from src.targets.resolver import TargetResolver


class CliOptionsLike(Protocol):
    target_url: str | None
    target_ref: str | None
    target_subdir: str | None
    output_dir: str | None


@dataclass(frozen=True)
class ScanResult:
    """CLI / Web UI の双方で利用する診断結果。"""

    target: ResolvedTarget
    output_dir: Path | None
    report_path: Path | None
    report_markdown: str
    generated_at: datetime
    loaded_rule_count: int
    executed_rule_count: int
    records: Sequence[RiskRecord]
    errors: Sequence[Tuple[str, str]]


class SecurityScan:
    """ローカルまたは remote archive の対象を診断し、結果を出力する。"""

    def __init__(
        self,
        project_root: Path,
        cli_options: CliOptionsLike | None = None,
        persist_report: bool = True,
    ) -> None:
        self._project_root = project_root
        self._cli_options = cli_options
        self._persist_report = persist_report

    def run(self) -> ScanResult:
        config = ScanConfig(self._project_root, self._config_overrides())
        target_spec = config.resolve_target_spec()
        output_dir = config.resolve_output_dir() if self._persist_report else None
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

            report_writer = ReportWriter(output_dir or self._project_root)
            report_markdown = report_writer.build_markdown(
                resolved.scan_path, records, errors, generated_at
            )
            report_path = None
            if self._persist_report and output_dir is not None:
                report_path = ReportWriter(output_dir).write(
                    resolved.scan_path, records, errors, generated_at
                )
            result = ScanResult(
                target=resolved,
                output_dir=output_dir,
                report_path=report_path,
                report_markdown=report_markdown,
                generated_at=generated_at,
                loaded_rule_count=len(rules),
                executed_rule_count=executed_count,
                records=records,
                errors=errors,
            )

            self._print_result(result)
            return result

    @staticmethod
    def _print_result(result: ScanResult) -> None:
        print(f"対象: {result.target.display_name}")
        print(f"スキャンパス: {result.target.scan_path}")
        print(f"取得方式: {result.target.fetch_mode}")
        print(f"出力先: {result.output_dir or '(保存なし)'}")
        print(f"読み込みルール数: {result.loaded_rule_count}")
        print(f"実行ルール数: {result.executed_rule_count}")
        print(f"検知件数: {len(result.records)}")
        if result.errors:
            print(f"失敗したルール数: {len(result.errors)}", file=sys.stderr)
        print(f"レポート: {result.report_path or '(メモリ上で生成)'}")

    def _config_overrides(self) -> ConfigOverrides:
        if self._cli_options is None:
            return ConfigOverrides()
        return ConfigOverrides(
            target_url=self._cli_options.target_url,
            target_ref=self._cli_options.target_ref,
            target_subdir=self._cli_options.target_subdir,
            output_dir=self._cli_options.output_dir,
        )
