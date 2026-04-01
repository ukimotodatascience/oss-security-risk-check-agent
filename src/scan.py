"""診断の実行フロー（設定読込 → ルール実行 → レポート）。"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from src.config import ScanConfig
from src.reporting import ReportWriter
from src.rule_engine import load_all_rules, run_all


class SecurityScan:
    """`TARGET_DIR` を診断し、結果を `OUTPUT_DIR` に出力するアプリケーション。"""

    def __init__(self, project_root: Path) -> None:
        self._project_root = project_root

    def run(self) -> None:
        config = ScanConfig(self._project_root)
        target = config.resolve_target_dir()
        output_dir = config.resolve_output_dir()

        rules = load_all_rules(self._project_root)
        if not rules:
            raise SystemExit(
                "ルールが 1 つも読み込めませんでした。src/rules の構成を確認してください。"
            )

        generated_at = datetime.now(timezone.utc)
        records, errors, executed_count = run_all(target, rules)

        report_path = ReportWriter(output_dir).write(
            target, records, errors, generated_at
        )

        print(f"対象: {target}")
        print(f"出力先: {output_dir}")
        print(f"読み込みルール数: {len(rules)}")
        print(f"実行ルール数: {executed_count}")
        print(f"検知件数: {len(records)}")
        if errors:
            print(f"失敗したルール数: {len(errors)}", file=sys.stderr)
        print(f"レポート: {report_path}")
