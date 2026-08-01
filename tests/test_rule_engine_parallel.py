from __future__ import annotations

import time
from pathlib import Path
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


class CrashThreadRule:
    rule_id = "M-CRASH"
    category = "mock"
    title = "Crash Thread Rule"
    severity = Severity.LOW

    def evaluate(self, target: Path) -> list[RiskRecord]:
        return []


def test_run_all_thread_crash_reports_rule_id(monkeypatch, tmp_path):
    # スレッド起動中のエラーを模擬するため、_evaluate_rule_thread の呼び出し時に例外を投げるようにモックする
    from src import rule_engine

    def fake_evaluate_rule_thread(*args, **kwargs):
        raise RuntimeError("Simulated thread bootstrap crash")

    monkeypatch.setattr(rule_engine, "_evaluate_rule_thread", fake_evaluate_rule_thread)

    rules = [CrashThreadRule()]
    callback_calls = []

    def progress_callback(index, total, rule_id):
        callback_calls.append((index, total, rule_id))

    records, errors, executed_count = run_all(
        tmp_path, rules, progress_callback=progress_callback
    )

    # 1. 失敗したエラーレコードの rule_id が "M-CRASH" になっていること（"unknown" ではない）
    assert len(errors) == 1
    assert errors[0][0] == "M-CRASH"
    assert "Simulated thread bootstrap crash" in errors[0][1]

    # 2. 進捗コールバック（完了通知）が正しく呼ばれていること
    # 完了通知 (1, 1, "M-CRASH")
    assert (1, 1, "M-CRASH") in callback_calls
    assert executed_count == 1


def test_run_all_callback_exception_handling(tmp_path):
    # progress_callback が例外を送出しても、ルール全体が失敗と判定されず、
    # 正常に結果が返されることを検証する。
    rules = [FastRule()]

    def bad_callback(index, total, rule_id):
        raise ValueError("Bad callback exception")

    records, errors, executed_count = run_all(
        tmp_path, rules, progress_callback=bad_callback
    )

    # コールバックの例外によってルール自体がエラーとしてマークされないこと
    assert len(errors) == 0
    assert len(records) == 1
    assert records[0].rule_id == "M-1"
    assert executed_count == 1
