"""ルール実行。"""

from __future__ import annotations

import concurrent.futures
import copyreg
import importlib
import inspect
import logging
import math
import os
import pickle
import signal
import threading
import traceback
from pathlib import Path
from typing import Any, Callable, List, Sequence, Tuple

from src.models import RiskRecord


# threading.local を pickle 可能にする設定を登録 (E402 回避のためインポート文の後に配置)
def _reconstruct_local(state: dict[str, Any]) -> threading.local:
    local_obj = threading.local()
    local_obj.__dict__.update(state)
    return local_obj


def _pickle_local(local_obj: threading.local) -> Tuple[Callable, Tuple[dict[str, Any]]]:
    try:
        state = local_obj.__dict__.copy()
    except AttributeError:
        state = {}
    return _reconstruct_local, (state,)


copyreg.pickle(threading.local, _pickle_local)


def _worker_initializer() -> None:
    """プロセスプールのワーカープロセス初期化時に新しいプロセスグループを作成する。"""
    import os

    if hasattr(os, "setpgrp"):
        try:
            os.setpgrp()
        except Exception:
            pass


logger = logging.getLogger(__name__)


def _rule_sort_key(rule_id: str) -> Tuple[str, int, str]:
    """`A-1`, `A-10` のようなルール ID をカテゴリ・番号順に並べる。"""
    category, separator, number_text = rule_id.partition("-")
    if separator and number_text.isdigit():
        return category, int(number_text), rule_id
    return rule_id, 0, rule_id


def load_all_rules(project_root: Path) -> List[Any]:
    """`src/rules` 配下の Rule クラスを動的に読み込み、インスタンス化して返す。"""
    rules: List[Any] = []
    src_dir = project_root / "src"
    rules_dir = src_dir / "rules"

    for py_file in rules_dir.rglob("*.py"):
        if py_file.name in {"__init__.py", "rule_template.py"}:
            continue

        module_path = py_file.relative_to(src_dir).with_suffix("")
        module_name = "src." + ".".join(module_path.parts)
        module = importlib.import_module(module_name)

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module_name:
                continue
            if not obj.__name__.endswith("Rule"):
                continue
            if not hasattr(obj, "evaluate"):
                continue
            rules.append(obj())

    return rules


def _evaluate_rule_in_process(
    rule_bytes: bytes,
    target: Path,
    cache_dir: Path | None,
    cache_ttl: int | None,
) -> List[RiskRecord]:
    """子プロセス内でルールを評価する。"""
    import copyreg
    import pickle
    import threading
    from src.rules.B_dependencies.vuln_sources import VulnLookupService

    # 子プロセス側でも threading.local の pickle を登録
    copyreg.pickle(threading.local, _pickle_local)

    rule = pickle.loads(rule_bytes)
    with VulnLookupService.use_config(cache_dir, cache_ttl):
        return rule.evaluate(target)


def run_all(
    target: Path,
    rules: Sequence[Any],
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> Tuple[List[RiskRecord], List[Tuple[str, str]], int]:
    """各ルールを1つずつ実行し、検知結果・失敗情報・実行数を返す。タイムアウト制御あり。"""
    records: List[RiskRecord] = []
    errors: List[Tuple[str, str]] = []
    executed_count = 0

    timeout_sec_str = os.environ.get("RULE_TIMEOUT_SEC", "300")
    try:
        timeout_sec = float(timeout_sec_str)
        if not math.isfinite(timeout_sec) or timeout_sec <= 0:
            raise ValueError("RULE_TIMEOUT_SEC は正の有限値である必要があります。")
    except ValueError:
        logger.warning(
            f"RULE_TIMEOUT_SEC の指定が無効です: '{timeout_sec_str}'。デフォルトの 300 秒を使用します。"
        )
        timeout_sec = 300.0

    sorted_rules = sorted(
        rules,
        key=lambda rule: _rule_sort_key(getattr(rule, "rule_id", type(rule).__name__)),
    )
    total = len(sorted_rules)

    # 脆弱性キャッシュ設定 of 伝播用パラメータを取得
    from src.rules.B_dependencies.vuln_sources import VulnLookupService

    cache_dir = getattr(VulnLookupService._active_config, "cache_dir", None)
    cache_ttl = getattr(VulnLookupService._active_config, "cache_ttl", None)

    # 実行中のルールを強制終了できるように ProcessPoolExecutor を使用
    executor = concurrent.futures.ProcessPoolExecutor(
        max_workers=1, initializer=_worker_initializer
    )
    try:
        for index, rule in enumerate(sorted_rules, start=1):
            rule_id = getattr(rule, "rule_id", type(rule).__name__)
            if progress_callback is not None:
                progress_callback(index, total, rule_id)

            executed_count += 1

            # executor.submit 自体および結果待ちを try ブロックで包み、壊れたプールの再生成を安全に行う
            try:
                rule_bytes = pickle.dumps(rule)
                future = executor.submit(
                    _evaluate_rule_in_process,
                    rule_bytes,
                    target,
                    cache_dir,
                    cache_ttl,
                )
                found = future.result(timeout=timeout_sec)
                if found:
                    records.extend(found)
            except concurrent.futures.TimeoutError:
                msg = f"ルール {rule_id} の実行がタイムアウト（{timeout_sec}秒）しました。"
                logger.error(msg)
                errors.append(
                    (
                        rule_id,
                        f"TimeoutError: Rule execution timed out after {timeout_sec} seconds.",
                    )
                )

                # ハングした子プロセスおよびそのすべての子孫プロセスを強制終了する
                for p in list(executor._processes.values()):
                    if p.pid is not None:
                        # 1. UNIX環境ではプロセスグループIDを指定して一括終了を試みる
                        pgid_killed = False
                        if hasattr(os, "killpg"):
                            try:
                                os.killpg(p.pid, signal.SIGTERM)
                                pgid_killed = True
                            except Exception:
                                pass

                        # 2. psutil を使用して再帰的にプロセスツリー全体（孫プロセス含む）を終了させる
                        try:
                            import psutil

                            parent = psutil.Process(p.pid)
                            children = parent.children(recursive=True)
                            for child in children:
                                try:
                                    child.terminate()
                                except Exception:
                                    pass
                        except Exception:
                            pass

                        # ワーカー自体の終了
                        try:
                            p.terminate()
                        except Exception:
                            pass

                        # 待機
                        try:
                            p.join(timeout=1.0)
                        except Exception:
                            pass

                        # それでも生存している場合は SIGKILL / kill を送信
                        if p.is_alive():
                            if hasattr(os, "killpg") and pgid_killed:
                                try:
                                    os.killpg(p.pid, signal.SIGKILL)
                                except Exception:
                                    pass
                            try:
                                import psutil

                                parent = psutil.Process(p.pid)
                                children = parent.children(recursive=True)
                                for child in children:
                                    try:
                                        child.kill()
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            try:
                                p.kill()
                                p.join(timeout=1.0)
                            except Exception:
                                pass

                executor.shutdown(wait=False)
                executor = concurrent.futures.ProcessPoolExecutor(
                    max_workers=1, initializer=_worker_initializer
                )
            except (concurrent.futures.process.BrokenProcessPool, BrokenPipeError):
                logger.error(
                    f"ルール {rule_id} の実行プロセスがクラッシュ（BrokenProcessPool）しました。"
                )
                errors.append(
                    (
                        rule_id,
                        "BrokenProcessPool: Subprocess terminated unexpectedly.",
                    )
                )
                # 壊れたプールを安全に再作成する
                executor.shutdown(wait=False)
                executor = concurrent.futures.ProcessPoolExecutor(
                    max_workers=1, initializer=_worker_initializer
                )
            except Exception:
                tb = traceback.format_exc()
                logger.exception(f"ルール {rule_id} の実行中にエラーが発生しました。")
                errors.append((rule_id, tb))
    finally:
        executor.shutdown(wait=False)

    return records, errors, executed_count
