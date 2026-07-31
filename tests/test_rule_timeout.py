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
        "B-1ルールのための推定依存件数: 55件。実行タイムアウトとして 9900.0秒 を適用します。"
        in record.message
        for record in caplog.records
    )


def test_run_all_b1_timeout_scoping_limit_300(tmp_path, monkeypatch, caplog):
    import logging

    # RULE_TIMEOUT_SEC をアンセット状態にする
    monkeypatch.delenv("RULE_TIMEOUT_SEC", raising=False)

    # 400件の依存関係を含む requirements.txt を作成する
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("\n".join(f"package-{i}==1.0" for i in range(400)))

    rules = [TestDynamicTimeoutValidationRule()]
    with caplog.at_level(logging.INFO, logger="src.rule_engine"):
        records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert errors == []
    assert any(
        "B-1ルールのための推定依存件数: 300件。実行タイムアウトとして 54000.0秒 を適用します。"
        in record.message
        for record in caplog.records
    )


def test_run_all_b1_timeout_scoping_recursive(tmp_path, monkeypatch, caplog):
    import logging
    import json

    # RULE_TIMEOUT_SEC をアンセット状態にする
    monkeypatch.delenv("RULE_TIMEOUT_SEC", raising=False)

    # 3階層下の深いディレクトリに 35件の依存関係を含む requirements.txt を作成する
    deep_dir = tmp_path / "apps" / "web" / "backend"
    deep_dir.mkdir(parents=True, exist_ok=True)
    req_file = deep_dir / "requirements.txt"
    req_file.write_text("\n".join(f"package-{i}==1.0" for i in range(35)))

    # 2階層下の深いディレクトリに 15件の依存関係を含む package.json を作成する
    another_deep_dir = tmp_path / "packages" / "lib"
    another_deep_dir.mkdir(parents=True, exist_ok=True)
    pkg_file = another_deep_dir / "package.json"
    pkg_data = {
        "dependencies": {f"dep-{i}": "^1.0.0" for i in range(10)},
        "devDependencies": {f"dev-dep-{i}": "^1.0.0" for i in range(5)},
    }
    pkg_file.write_text(json.dumps(pkg_data))

    rules = [TestDynamicTimeoutValidationRule()]
    with caplog.at_level(logging.INFO, logger="src.rule_engine"):
        records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert errors == []
    assert any(
        "B-1ルールのための推定依存件数: 50件。実行タイムアウトとして 9000.0秒 を適用します。"
        in record.message
        for record in caplog.records
    )


def test_run_all_b1_timeout_scoping_with_custom_env(tmp_path, monkeypatch, caplog):
    import logging

    # RULE_TIMEOUT_SEC をアンセット状態にする
    monkeypatch.delenv("RULE_TIMEOUT_SEC", raising=False)

    # カスタムのAPIタイムアウトと再試行回数を設定する
    monkeypatch.setenv("VULN_API_TIMEOUT_SEC", "60.0")
    monkeypatch.setenv("VULN_MAX_RETRIES", "2")

    # 10件の依存関係を含む requirements.txt を作成する
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("\n".join(f"package-{i}==1.0" for i in range(10)))

    # 1依存あたり 3 * (1 + 2) * 60 * 1.5 = 810.0 秒
    # 10件で 8100.0 秒
    rules = [TestDynamicTimeoutValidationRule()]
    with caplog.at_level(logging.INFO, logger="src.rule_engine"):
        records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == 1
    assert errors == []
    assert any(
        "B-1ルールのための推定依存件数: 10件。実行タイムアウトとして 8100.0秒 を適用します。"
        in record.message
        for record in caplog.records
    )


def test_estimate_dependency_count_safe_excludes_symlink(tmp_path):
    from src.rule_engine import _estimate_dependency_count_safe

    # 実際のディレクトリとファイル
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    real_file = real_dir / "requirements.txt"
    real_file.write_text("package-a==1.0\npackage-b==1.0")

    # シンボリックリンクファイル
    symlink_file = tmp_path / "requirements_link.txt"
    try:
        symlink_file.symlink_to(real_file)
    except OSError:
        # Windowsの権限エラー等で作成できない場合はテストをスキップ
        return

    # シンボリックリンクディレクトリ
    symlink_dir = tmp_path / "sym_dir"
    try:
        symlink_dir.symlink_to(real_dir, target_is_directory=True)
    except OSError:
        return

    # シンボリックリンク経由で辿った場合は依存関係数が増えるが、
    # シンボリックリンクを辿らないため、カウントは real_dir の requirements.txt (2件) のみになるはず
    count = _estimate_dependency_count_safe(tmp_path)
    # 最低値は 5
    assert count == 5


class TestInternalTimeoutErrorRule:
    rule_id = "InternalTimeoutRule"

    def evaluate(self, target):
        raise TimeoutError("Simulated internal timeout error")


class TestGetPidRule:
    rule_id = "GetPidRule"

    def evaluate(self, target):
        import os
        from src.models import RiskRecord

        return [
            RiskRecord(
                rule_id="GetPidRule",
                category="test",
                title="test",
                severity="Medium",
                file_path=str(target),
                line=1,
                message=str(os.getpid()),
            )
        ]


def test_run_all_b1_internal_timeout_error_propagation(tmp_path):
    rules = [TestInternalTimeoutErrorRule()]
    records, errors, executed_count = run_all(tmp_path, rules)
    assert executed_count == 1
    assert len(errors) == 1
    assert errors[0][0] == "InternalTimeoutRule"
    assert "TimeoutError: Simulated internal timeout error" in errors[0][1]


def test_run_all_global_executor_caches_reused(tmp_path):
    from src.rule_engine import _reset_global_executor

    # テスト開始前に executor をリセットしてクリーンな状態にする
    _reset_global_executor()

    rules = [TestGetPidRule()]

    # 1回目のスキャン
    records1, errors1, count1 = run_all(tmp_path, rules)
    assert len(records1) == 1
    pid1 = records1[0].message

    # 2回目のスキャン
    records2, errors2, count2 = run_all(tmp_path, rules)
    assert len(records2) == 1
    pid2 = records2[0].message

    # プロセスプールが再利用されているため、PIDは一致するはず
    assert pid1 == pid2


class SlowRule:
    rule_id = "SlowRule"

    def evaluate(self, target):
        import time

        time.sleep(0.5)
        return []


def test_run_all_concurrency_lock(tmp_path):
    import threading
    import time

    rules = [SlowRule()]

    results = []

    def worker():
        records, errors, count = run_all(tmp_path, rules)
        results.append((records, errors, count))

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)

    t1.start()
    time.sleep(0.1)
    t2.start()

    t1.join()
    t2.join()

    assert len(results) == 2
    assert results[0][1] == []
    assert results[1][1] == []
