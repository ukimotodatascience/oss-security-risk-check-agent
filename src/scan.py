"""診断の実行フロー（設定読込 → ルール実行 → レポート）。"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, ContextManager, Protocol, Sequence, Tuple

from src.config import ConfigOverrides, ScanConfig
from src.models import RiskRecord
from src.reporting import ReportWriter
from src.rule_engine import load_all_rules, run_all
from src.targets.archive_fetcher import ArchiveSnapshotFetcher
from src.targets.models import (
    RemoteFetchLimits,
    ResolvedTarget,
    ScanTargetSpec,
    SkippedFile,
)
from src.targets.resolver import TargetResolver


class CliOptionsLike(Protocol):
    target_url: str | None
    target_ref: str | None
    target_subdir: str | None
    output_dir: str | None


class ScanConfigLike(Protocol):
    def resolve_target_spec(self) -> ScanTargetSpec: ...

    def resolve_output_dir(self) -> Path | None: ...

    def resolve_remote_fetch_limits(self) -> RemoteFetchLimits: ...


class TargetResolverLike(Protocol):
    def resolve(self, spec: ScanTargetSpec) -> ContextManager[ResolvedTarget]: ...


ConfigFactory = Callable[[Path, ConfigOverrides | None], ScanConfigLike]
TargetResolverFactory = Callable[[Any], TargetResolverLike]
RuleLoader = Callable[[Path], Sequence[Any]]
RuleRunner = Callable[
    [
        Path,
        Sequence[Any],
        Callable[[int, int, str], None] | None,
    ],
    Tuple[Sequence[RiskRecord], Sequence[Tuple[str, str]], int],
]
StepProgressCallback = Callable[[int, int, str], None]


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
    skipped_files: Sequence[SkippedFile]


class SecurityScan:
    """ローカルまたは remote archive の対象を診断し、結果を出力する。"""

    _PROGRESS_BAR_WIDTH = 24

    def __init__(
        self,
        project_root: Path,
        cli_options: CliOptionsLike | None = None,
        persist_report: bool = True,
        step_progress_callback: StepProgressCallback | None = None,
        config_factory: ConfigFactory | None = None,
        target_resolver_factory: TargetResolverFactory | None = None,
        rule_loader: RuleLoader | None = None,
        rule_runner: RuleRunner | None = None,
    ) -> None:
        self._project_root = project_root
        self._cli_options = cli_options
        self._persist_report = persist_report
        self._step_progress_callback = step_progress_callback
        self._config_factory = config_factory or ScanConfig
        self._target_resolver_factory = target_resolver_factory or TargetResolver
        self._rule_loader = rule_loader or load_all_rules
        self._rule_runner = rule_runner or run_all

    def run(self) -> ScanResult:
        self._notify_step_progress(1, 5, "設定を読み込んでいます")
        config = self._config_factory(self._project_root, self._config_overrides())
        target_spec = config.resolve_target_spec()
        output_dir = config.resolve_output_dir() if self._persist_report else None
        limits = config.resolve_remote_fetch_limits()

        self._notify_step_progress(2, 5, "スキャン対象を解決しています")
        fetcher = ArchiveSnapshotFetcher(
            max_download_bytes=limits.max_download_bytes,
            max_extracted_bytes=limits.max_extracted_bytes,
            max_files=limits.max_files,
            max_single_file_bytes=limits.max_single_file_bytes,
            timeout_sec=limits.timeout_sec,
        )
        resolver = self._target_resolver_factory(fetcher)

        self._notify_step_progress(3, 5, "ルールを読み込んでいます")
        rules = self._rule_loader(self._project_root)
        if not rules:
            raise SystemExit(
                "ルールが 1 つも読み込めませんでした。src/rules の構成を確認してください。"
            )

        generated_at = datetime.now(timezone.utc)
        with resolver.resolve(target_spec) as resolved:
            self._notify_step_progress(4, 5, "ルールを実行しています")
            records, errors, executed_count = self._rule_runner(
                resolved.scan_path,
                rules,
                self._print_rule_progress,
            )

            self._notify_step_progress(5, 5, "レポートを生成しています")
            report_writer = ReportWriter(output_dir or self._project_root)
            report_markdown = report_writer.build_markdown(
                resolved.scan_path,
                records,
                errors,
                generated_at,
                resolved.skipped_files,
            )
            report_path = None
            if self._persist_report and output_dir is not None:
                report_path = ReportWriter(output_dir).write(
                    resolved.scan_path,
                    records,
                    errors,
                    generated_at,
                    resolved.skipped_files,
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
                skipped_files=resolved.skipped_files,
            )

            self._print_result(result)
            return result

    @staticmethod
    def _print_progress_step(current: int, total: int, message: str) -> None:
        bar = SecurityScan._format_progress_bar(current, total)
        percent = SecurityScan._format_percent(current, total)
        print(f"[{current}/{total}] {bar} {percent} {message}")

    def _notify_step_progress(self, current: int, total: int, message: str) -> None:
        self._print_progress_step(current, total, message)
        if self._step_progress_callback is not None:
            self._step_progress_callback(current, total, message)

    @staticmethod
    def _print_rule_progress(current: int, total: int, rule_id: str) -> None:
        bar = SecurityScan._format_progress_bar(current, total)
        percent = SecurityScan._format_percent(current, total)
        print(f"    - ルール実行中 [{current:>3}/{total}] {bar} {percent} {rule_id}")

    @classmethod
    def _format_progress_bar(cls, current: int, total: int) -> str:
        if total <= 0:
            return "[------------------------]"

        bounded_current = min(max(current, 0), total)
        filled = int((bounded_current / total) * cls._PROGRESS_BAR_WIDTH)
        if bounded_current == total:
            filled = cls._PROGRESS_BAR_WIDTH
        empty = cls._PROGRESS_BAR_WIDTH - filled
        return f"[{'#' * filled}{'-' * empty}]"

    @staticmethod
    def _format_percent(current: int, total: int) -> str:
        if total <= 0:
            return "  0%"
        bounded_current = min(max(current, 0), total)
        return f"{int((bounded_current / total) * 100):>3}%"

    @staticmethod
    def _print_result(result: ScanResult) -> None:
        print(f"対象: {result.target.display_name}")
        print(f"スキャンパス: {result.target.scan_path}")
        print(f"取得方式: {result.target.fetch_mode}")
        print(f"出力先: {result.output_dir or '(保存なし)'}")
        print(f"読み込みルール数: {result.loaded_rule_count}")
        print(f"実行ルール数: {result.executed_rule_count}")
        print(f"検知件数: {len(result.records)}")
        if result.skipped_files:
            print(f"スキップしたファイル数: {len(result.skipped_files)}")
            for skipped in result.skipped_files:
                print(f"  - {skipped.path}: {skipped.reason}")
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
