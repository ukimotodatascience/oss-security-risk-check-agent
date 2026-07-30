import time
import threading
import pytest
from pathlib import Path
from src.rule_engine import run_all
from src.models import RiskRecord, Severity


# テスト用のダミールールをモジュールトップレベルに定義
# （子プロセスからの動的インポート・シリアライズを可能にするため）
class TestNormalRule:
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


class TestHangRule:
    rule_id = "A-2"

    def evaluate(self, target: Path):
        # タイムアウト（0.2秒）より十分長いスリープを実行してタイムアウトを誘発する。
        # プロセスのハングアップを防ぐため、無限ループではなく有限時間で終了させる。
        time.sleep(5.0)
        return []


class TestPostRule:
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


class TestFallbackRule:
    rule_id = "A-1"

    def evaluate(self, target: Path):
        return []


class TestDummyB1Rule:
    rule_id = "B-1"

    def evaluate(self, target: Path):
        # 子プロセス内で実行される evaluate メソッド内で
        # VulnLookupService のアクティブ設定が正しく伝播していることを確認
        from src.rules.B_dependencies.vuln_sources import VulnLookupService

        svc = VulnLookupService()
        # _cache_dir はカスタム設定から伝播していることを確認
        assert svc._cache_dir.parent.name == "custom_vuln_cache"
        assert svc._cache_ttl == 9999
        return []


class DummyThreadLocalStateRule:
    rule_id = "C-1"

    def __init__(self) -> None:
        self.state = threading.local()
        # スレッドローカル状態にテスト用の属性を設定
        self.state.test_val = "secret_state_value"

    def evaluate(self, target: Path):
        # 子プロセス内で self.state.test_val が正しく引き継がれていることを確認
        assert getattr(self.state, "test_val", None) == "secret_state_value"
        return [
            RiskRecord(
                rule_id=self.rule_id,
                category="code",
                title="State Propagation Alert",
                severity=Severity.LOW,
                file_path=target / "dummy.py",
                line=1,
                message=self.state.test_val,
            )
        ]


def test_run_all_with_rule_timeout(tmp_path, monkeypatch):
    # タイムアウト値を環境変数で短く設定 (プロセスプールの起動時間を考慮して 1.0 秒)
    monkeypatch.setenv("RULE_TIMEOUT_SEC", "1.0")

    rules = [TestNormalRule(), TestHangRule(), TestPostRule()]

    records, errors, executed_count = run_all(tmp_path, rules)

    # 実行数は3であるべき
    assert executed_count == 3

    # TestNormalRule と TestPostRule の結果は取得できているべき
    rule_ids_in_records = {r.rule_id for r in records}
    assert "A-1" in rule_ids_in_records
    assert "A-3" in rule_ids_in_records
    assert "A-2" not in rule_ids_in_records

    # エラー情報に TestHangRule (A-2) が登録されているべき
    assert len(errors) == 1
    err_rule_id, err_msg = errors[0]
    assert err_rule_id == "A-2"
    assert "TimeoutError" in err_msg


@pytest.mark.parametrize("invalid_val", ["invalid_value", "nan", "inf", "-5", "0"])
def test_run_all_invalid_timeout_fallback(tmp_path, monkeypatch, caplog, invalid_val):
    monkeypatch.setenv("RULE_TIMEOUT_SEC", invalid_val)

    rules = [TestFallbackRule()]

    import logging

    # root または src.rule_engine の logger をキャプチャ
    with caplog.at_level(logging.WARNING, logger="src.rule_engine"):
        records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert any("RULE_TIMEOUT_SEC" in record.message for record in caplog.records)


def test_run_all_propagates_vuln_cache_config(tmp_path):
    from src.rules.B_dependencies.vuln_sources import VulnLookupService

    custom_cache_dir = tmp_path / "custom_vuln_cache"
    custom_ttl = 9999

    rules = [TestDummyB1Rule()]

    with VulnLookupService.use_config(custom_cache_dir, custom_ttl):
        records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert errors == []


def test_run_all_propagates_thread_local_dict_state(tmp_path):
    rules = [DummyThreadLocalStateRule()]

    records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert errors == []
    assert len(records) == 1
    assert records[0].message == "secret_state_value"


class TestCrashRule:
    rule_id = "A-4"

    def evaluate(self, target: Path):
        import os

        # プロセスを即座に異常終了させて BrokenProcessPool を誘発する
        os._exit(1)


def test_run_all_recovers_from_broken_process_pool(tmp_path):
    rules = [TestCrashRule(), TestPostRule()]

    records, errors, executed_count = run_all(tmp_path, rules)

    # 実行数は 2 であるべき
    assert executed_count == 2

    # A-4 は BrokenProcessPool エラーとして記録されているべき
    err_rule_ids = {err[0] for err in errors}
    assert "A-4" in err_rule_ids
    assert any("BrokenProcessPool" in err[1] for err in errors if err[0] == "A-4")

    # クラッシュ後、プールが再作成されて A-3 (TestPostRule) の結果は正常に取得できているべき
    rule_ids_in_records = {r.rule_id for r in records}
    assert "A-3" in rule_ids_in_records


class TestDynamicTimeoutValidationRule:
    rule_id = "B-1"

    def evaluate(self, target: Path):
        return []


def test_run_all_b1_timeout_scoping(tmp_path, monkeypatch, caplog):
    import logging
    import json

    # RULE_TIMEOUT_SEC をアンセット状態にする
    monkeypatch.delenv("RULE_TIMEOUT_SEC", raising=False)

    # 35件の依存関係を含む requirements.txt を作成する
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("\n".join(f"package-{i}==1.0" for i in range(35)))

    # 20件の依存関係を含む package.json を作成する (4つのフィールドを合計)
    pkg_file = tmp_path / "package.json"
    pkg_data = {
        "dependencies": {f"dep-{i}": "^1.0.0" for i in range(10)},
        "devDependencies": {f"dev-dep-{i}": "^1.0.0" for i in range(5)},
        "optionalDependencies": {f"opt-dep-{i}": "^1.0.0" for i in range(3)},
        "peerDependencies": {f"peer-dep-{i}": "^1.0.0" for i in range(2)},
    }
    pkg_file.write_text(json.dumps(pkg_data))

    rules = [TestDynamicTimeoutValidationRule()]
    with caplog.at_level(logging.INFO, logger="src.rule_engine"):
        records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert errors == []
    assert any(
        "B-1ルールのための推定依存件数: 55件。実行タイムアウトとして 5500.0秒 を適用します。"
        in record.message
        for record in caplog.records
    )
