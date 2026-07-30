import os
import time
import pytest
from pathlib import Path
from src.rule_engine import run_all
from src.models import RiskRecord, Severity


def test_run_all_with_rule_timeout(tmp_path, monkeypatch):
    # タイムアウト値を環境変数で短く設定
    monkeypatch.setenv("RULE_TIMEOUT_SEC", "0.2")

    class NormalRule:
        rule_id = "A-1"

        def evaluate(self, target: Path):
            return [
                RiskRecord(
                    rule_id=self.rule_id,
                    category="code",
                    title="Normal Alert",
                    severity=Severity.LOW,
                    file_path=target / "dummy.py",
                    line=1,
                    message="Normal find",
                )
            ]

    class HangRule:
        rule_id = "A-2"

        def evaluate(self, target: Path):
            # タイムアウト（0.2秒）より十分長いスリープを実行してタイムアウトを誘発する。
            # プロセスのハングアップを防ぐため、無限ループではなく有限時間で終了させる。
            time.sleep(5.0)
            return []

    class PostRule:
        rule_id = "A-3"

        def evaluate(self, target: Path):
            return [
                RiskRecord(
                    rule_id=self.rule_id,
                    category="code",
                    title="Post Alert",
                    severity=Severity.LOW,
                    file_path=target / "dummy.py",
                    line=2,
                    message="Post find",
                )
            ]

    rules = [NormalRule(), HangRule(), PostRule()]

    records, errors, executed_count = run_all(tmp_path, rules)

    # 実行数は3であるべき
    assert executed_count == 3

    # NormalRule と PostRule の結果は取得できているべき
    rule_ids_in_records = {r.rule_id for r in records}
    assert "A-1" in rule_ids_in_records
    assert "A-3" in rule_ids_in_records
    assert "A-2" not in rule_ids_in_records

    # エラー情報に HangRule (A-2) が登録されているべき
    assert len(errors) == 1
    err_rule_id, err_msg = errors[0]
    assert err_rule_id == "A-2"
    assert "TimeoutError" in err_msg


def test_run_all_invalid_timeout_fallback(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("RULE_TIMEOUT_SEC", "invalid_value")

    class NormalRule:
        rule_id = "A-1"

        def evaluate(self, target: Path):
            return []

    rules = [NormalRule()]

    import logging
    # root または src.rule_engine の logger をキャプチャ
    with caplog.at_level(logging.WARNING, logger="src.rule_engine"):
        records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert any("RULE_TIMEOUT_SEC" in record.message for record in caplog.records)
