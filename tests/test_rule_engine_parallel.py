from __future__ import annotations

import time
from pathlib import Path
import pytest
from src.models import Severity, RiskRecord
from src.rule_engine import run_all


class FastRule:
    rule_id = "M-1"
    category = "mock"
    title = "Fast Rule"
    severity = Severity.LOW

    def evaluate(self, target: Path) -> list[RiskRecord]:
        time.sleep(0.1)
        return [
            RiskRecord(
                rule_id=self.rule_id,
                category=self.category,
                title=self.title,
                severity=self.severity,
                file_path=target,
                line=1,
                message="Fast rule hit",
            )
        ]


class SlowRule:
    rule_id = "M-2"
    category = "mock"
    title = "Slow Timeout Rule"
    severity = Severity.HIGH

    def evaluate(self, target: Path) -> list[RiskRecord]:
        time.sleep(5.0)
        return []


def test_run_all_parallel_and_individual_timeout(monkeypatch, tmp_path):
    # RULE_TIMEOUT_SEC を 1.0秒に設定
    monkeypatch.setenv("RULE_TIMEOUT_SEC", "1.0")

    rules = [FastRule(), SlowRule()]

    start_time = time.time()
    records, errors, executed_count = run_all(tmp_path, rules)
    end_time = time.time()

    elapsed = end_time - start_time

    # 1. 実行時間が SlowRule (5秒) の完了を待たずに、タイムアウト (1.0秒) 付近で終了していること
    assert elapsed < 3.0

    # 2. FastRule の結果が正常に検知できていること
    assert len(records) == 1
    assert records[0].rule_id == "M-1"

    # 3. SlowRule がタイムアウトエラーとして記録されていること
    assert len(errors) == 1
    assert errors[0][0] == "M-2"
    assert "TimeoutError" in errors[0][1]

    assert executed_count == 2
