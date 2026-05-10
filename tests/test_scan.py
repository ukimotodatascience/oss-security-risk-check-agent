from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

import pytest

from src.config import ConfigOverrides
from src.models import RiskRecord, Severity
from src.targets.models import RemoteFetchLimits, ResolvedTarget, ScanTargetSpec


@dataclass(frozen=True)
class DummyCliOptions:
    target_url: str | None = None
    target_ref: str | None = None
    target_subdir: str | None = None
    output_dir: str | None = None


class FakeScanConfig:
    seen_overrides: ConfigOverrides | None = None

    def __init__(
        self, project_root: Path, overrides: ConfigOverrides | None = None
    ) -> None:
        self.project_root = project_root
        self.overrides = overrides
        FakeScanConfig.seen_overrides = overrides

    def resolve_target_spec(self) -> ScanTargetSpec:
        return ScanTargetSpec(source_type="local", local_dir=self.project_root)

    def resolve_output_dir(self) -> Path:
        return self.project_root / "reports"

    def resolve_remote_fetch_limits(self) -> RemoteFetchLimits:
        return RemoteFetchLimits(
            timeout_sec=1,
            max_download_bytes=1024,
            max_extracted_bytes=2048,
            max_files=10,
            max_single_file_bytes=512,
        )


class FakeTargetResolver:
    def __init__(self, fetcher: Any) -> None:
        self.fetcher = fetcher

    @contextmanager
    def resolve(self, spec: ScanTargetSpec) -> Iterator[ResolvedTarget]:
        scan_path = spec.local_dir or Path.cwd()
        yield ResolvedTarget(
            display_name="dummy-target",
            scan_path=scan_path,
            fetch_mode="local",
        )


class FakeRule:
    rule_id = "X-1"


def fake_load_all_rules(root: Path) -> list[FakeRule]:
    return [FakeRule()]


def fake_run_all_empty(
    target: Path,
    rules: Sequence[Any],
    progress_callback: Any = None,
) -> tuple[list[RiskRecord], list[tuple[str, str]], int]:
    return [], [], len(rules)


def test_security_scan_run_returns_result_without_persisting_report(tmp_path, capsys):
    from src import scan as scan_module

    record = RiskRecord(
        rule_id="X-1",
        title="Fake finding",
        severity=Severity.HIGH,
        category="test",
        file_path="app.py",
        line=10,
        message="detected",
    )

    def fake_run_all(
        target: Path,
        rules: Sequence[Any],
        progress_callback: Any = None,
    ) -> tuple[list[RiskRecord], list[tuple[str, str]], int]:
        if progress_callback is not None:
            progress_callback(1, len(rules), "X-1")
        return [record], [("Z-9", "traceback")], len(rules)

    result = scan_module.SecurityScan(
        tmp_path,
        persist_report=False,
        config_factory=FakeScanConfig,
        target_resolver_factory=FakeTargetResolver,
        rule_loader=fake_load_all_rules,
        rule_runner=fake_run_all,
    ).run()

    assert result.output_dir is None
    assert result.report_path is None
    assert result.loaded_rule_count == 1
    assert result.executed_rule_count == 1
    assert result.records == [record]
    assert result.errors == [("Z-9", "traceback")]
    assert "# OSS Security Risk Report" in result.report_markdown

    printed = capsys.readouterr()
    assert "[1/5]" in printed.out
    assert "設定を読み込んでいます" in printed.out
    assert "[4/5]" in printed.out
    assert "ルールを実行しています" in printed.out
    assert "ルール実行中" in printed.out
    assert "#" in printed.out
    assert "%" in printed.out
    assert "対象: dummy-target" in printed.out
    assert "失敗したルール数: 1" in printed.err


def test_security_scan_persists_report_when_output_dir_is_configured(tmp_path):
    from src import scan as scan_module

    result = scan_module.SecurityScan(
        tmp_path,
        persist_report=True,
        config_factory=FakeScanConfig,
        target_resolver_factory=FakeTargetResolver,
        rule_loader=fake_load_all_rules,
        rule_runner=fake_run_all_empty,
    ).run()

    assert result.output_dir == tmp_path / "reports"
    assert result.report_path is not None
    assert result.report_path.exists()
    assert result.report_path.read_text(encoding="utf-8").startswith(
        "# OSS Security Risk Report"
    )


def test_security_scan_exits_when_no_rules_are_loaded(tmp_path):
    from src import scan as scan_module

    def fake_load_no_rules(root: Path) -> list[FakeRule]:
        return []

    with pytest.raises(SystemExit, match="ルールが 1 つも読み込めませんでした"):
        scan_module.SecurityScan(
            tmp_path,
            config_factory=FakeScanConfig,
            target_resolver_factory=FakeTargetResolver,
            rule_loader=fake_load_no_rules,
        ).run()


def test_security_scan_builds_config_overrides_from_cli_options(tmp_path):
    from src import scan as scan_module

    options = DummyCliOptions(
        target_url="https://github.com/example/project",
        target_ref="main",
        target_subdir="backend",
        output_dir="reports",
    )

    scan_module.SecurityScan(
        tmp_path,
        cli_options=options,
        persist_report=False,
        config_factory=FakeScanConfig,
        target_resolver_factory=FakeTargetResolver,
        rule_loader=fake_load_all_rules,
        rule_runner=fake_run_all_empty,
    ).run()

    overrides = FakeScanConfig.seen_overrides
    assert overrides is not None
    assert overrides.target_url == options.target_url
    assert overrides.target_ref == options.target_ref
    assert overrides.target_subdir == options.target_subdir
    assert overrides.output_dir == options.output_dir
