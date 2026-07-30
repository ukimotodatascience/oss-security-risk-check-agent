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


def _estimate_dependency_count(target: Path) -> int:
    """診断対象ディレクトリ内の依存関係定義ファイルを走査し、大まかな依存件数をカウントする。"""
    count = 0
    if not target.exists():
        return 10

    dep_files = [
        "requirements.txt",
        "pyproject.toml",
        "package.json",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "Cargo.toml",
        "Pipfile",
        "poetry.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.lock",
    ]

    found_any = False
    for filename in dep_files:
        filepath = target / filename
        if filepath.is_file():
            found_any = True
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if filename == "package.json":
                    import json

                    data = json.loads(content)
                    deps = data.get("dependencies", {})
                    dev_deps = data.get("devDependencies", {})
                    count += len(deps) + len(dev_deps)
                elif filename == "requirements.txt":
                    lines = [
                        line.strip()
                        for line in content.splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    count += len(lines)
                elif filename == "pyproject.toml":
                    for line in content.splitlines():
                        if "dependencies" in line or "requires" in line:
                            count += 5
                elif filename == "go.mod":
                    count += content.count("require ")
                elif filename == "Cargo.toml":
                    count += content.count("[dependencies]") * 5
                elif "lock" in filename or "lock" in content:
                    count += min(
                        50, content.count("package") or content.count("name =") or 10
                    )
                else:
                    count += 10
            except Exception:
                count += 10

    if not found_any:
        return 10

    return max(5, count)


def _cleanup_executor_processes(
    executor: concurrent.futures.ProcessPoolExecutor,
) -> None:
    """ハングした、またはクラッシュしたワーカープロセスおよびそのすべての子孫プロセスを確実に強制終了する。"""
    import os

    try:
        processes = list(executor._processes.values())
    except Exception:
        return

    for p in processes:
        pid = p.pid
        if pid is None:
            continue

        # 1. psutilを用いて、親プロセスが消える前に子孫プロセスのPIDリストを取得しておく
        children_pids = []
        try:
            import psutil

            parent_proc = psutil.Process(pid)
            children_pids = [c.pid for c in parent_proc.children(recursive=True)]
        except Exception:
            pass

        # 2. プロセスグループ（UNIX）がある場合は、まず SIGTERM をグループ全体に送信
        pgid_killed = False
        if hasattr(os, "killpg"):
            try:
                os.killpg(pid, signal.SIGTERM)
                pgid_killed = True
            except Exception:
                pass

        # 3. 各子プロセスに個別に terminate() を送信
        for c_pid in children_pids:
            try:
                import psutil

                psutil.Process(c_pid).terminate()
            except Exception:
                pass

        # 4. ワーカー自体を終了
        try:
            p.terminate()
        except Exception:
            pass

        # 5. join で待機
        try:
            p.join(timeout=0.5)
        except Exception:
            pass

        # 6. ワーカー自身が終了したかに関わらず、子孫やグループ全体の残留に対して SIGKILL を送信する
        if hasattr(os, "killpg") and pgid_killed:
            try:
                os.killpg(pid, signal.SIGKILL)
            except Exception:
                pass

        for c_pid in children_pids:
            try:
                import psutil

                proc = psutil.Process(c_pid)
                if proc.is_running():
                    proc.kill()
            except Exception:
                pass

        try:
            if p.is_alive():
                p.kill()
                p.join(timeout=0.5)
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

    timeout_sec_str = os.environ.get("RULE_TIMEOUT_SEC")
    if timeout_sec_str is not None:
        try:
            timeout_sec = float(timeout_sec_str)
            if not math.isfinite(timeout_sec) or timeout_sec <= 0:
                raise ValueError("RULE_TIMEOUT_SEC は正の有限値である必要があります。")
        except ValueError:
            logger.warning(
                f"RULE_TIMEOUT_SEC の指定が無効です: '{timeout_sec_str}'。デフォルト値を使用します。"
            )
            timeout_sec_str = None

    if timeout_sec_str is None:
        # 依存関係件数に基づいて動的にタイムアウトを算出する (1件あたり最悪 100秒として計算、最低 300秒)
        dep_count = _estimate_dependency_count(target)
        timeout_sec = max(300.0, float(dep_count * 100.0))
        logger.info(
            f"推定依存件数: {dep_count}件。動的タイムアウト {timeout_sec}秒 を適用します。"
        )

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
                _cleanup_executor_processes(executor)

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
                # 壊れたプールから起動された子孫プロセスも含めて安全に回収する
                _cleanup_executor_processes(executor)
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
