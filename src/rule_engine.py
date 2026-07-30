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


def _setup_windows_job_object() -> None:
    """Windows環境で現在のプロセスをJob Objectに関連付け、クローズ時に子孫を自動的にkillするように設定する。"""
    import os

    if os.name != "nt":
        return

    import ctypes

    try:
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.windll.kernel32

        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p

        kernel32.SetInformationJobObject.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        kernel32.SetInformationJobObject.restype = ctypes.c_int

        kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.AssignProcessToJobObject.restype = ctypes.c_int

        kernel32.GetCurrentProcess.restype = ctypes.c_void_p

        h_job = kernel32.CreateJobObjectW(None, None)
        if not h_job:
            raise ctypes.WinError()

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        sizeof_info = ctypes.sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
        res = kernel32.SetInformationJobObject(
            h_job,
            9,  # JobObjectExtendedLimitInformation
            ctypes.byref(info),
            sizeof_info,
        )
        if not res:
            raise ctypes.WinError()

        h_process = kernel32.GetCurrentProcess()
        res = kernel32.AssignProcessToJobObject(h_job, h_process)
        if not res:
            raise ctypes.WinError()
    except Exception as e:
        logger.warning(f"Windows Job Object のセットアップに失敗しました: {e}")


def _worker_initializer() -> None:
    """プロセスプールのワーカープロセス初期化時に新しいプロセスグループを作成し、WindowsではJob Objectに登録する。"""
    import os

    if hasattr(os, "setpgrp"):
        try:
            os.setpgrp()
        except Exception:
            pass

    _setup_windows_job_object()


def _estimate_dependency_count_safe(target: Path) -> int:
    """親プロセスで安全かつ高速に依存関係件数を推定する（OOM/フリーズ防止制限付き）。"""
    if not target.exists():
        return 10

    count = 0
    files_scanned = 0
    total_entries_checked = 0
    dep_names = {
        "requirements.txt",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "Cargo.toml",
    }

    try:
        candidates = []
        # 直下および1階層下のディレクトリ走査（最大100エントリに制限）
        for p in target.iterdir():
            total_entries_checked += 1
            if total_entries_checked > 100:
                break

            if p.is_file() and (
                p.name in dep_names or p.name.startswith("requirements")
            ):
                candidates.append(p)
            elif p.is_dir() and p.name not in {
                ".git",
                "node_modules",
                ".venv",
                "venv",
                "__pycache__",
            }:
                try:
                    for sub_p in p.iterdir():
                        total_entries_checked += 1
                        if total_entries_checked > 100:
                            break
                        if sub_p.is_file() and (
                            sub_p.name in dep_names
                            or sub_p.name.startswith("requirements")
                        ):
                            candidates.append(sub_p)
                except Exception:
                    pass

        for filepath in candidates:
            if files_scanned >= 20:
                break

            try:
                stat = filepath.stat()
                # 1ファイルあたり 500KB 上限
                if stat.st_size > 500 * 1024:
                    count += 50
                    continue

                files_scanned += 1
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if filepath.name == "package.json":
                    import json

                    try:
                        data = json.loads(content)
                        for field in (
                            "dependencies",
                            "devDependencies",
                            "optionalDependencies",
                            "peerDependencies",
                        ):
                            deps = data.get(field, {})
                            if isinstance(deps, dict):
                                count += len(deps)
                    except Exception:
                        count += 10
                elif filepath.name == "requirements.txt" or filepath.name.startswith(
                    "requirements"
                ):
                    lines = [
                        line.strip()
                        for line in content.splitlines()
                        if line.strip() and not line.strip().startswith("#")
                    ]
                    count += len(lines)
                elif filepath.name == "pyproject.toml":
                    lines = content.splitlines()
                    in_deps_section = False
                    for line in lines:
                        line = line.strip()
                        if line.startswith("[") and "dependencies" in line:
                            in_deps_section = True
                        elif line.startswith("["):
                            in_deps_section = False
                        elif in_deps_section and line and not line.startswith("#"):
                            count += 1
                elif filepath.name == "go.mod":
                    count += content.count("require ")
                elif filepath.name == "Cargo.toml":
                    lines = content.splitlines()
                    in_deps = False
                    for line in lines:
                        line = line.strip()
                        if line.startswith("[dependencies]") or line.startswith(
                            "[dev-dependencies]"
                        ):
                            in_deps = True
                        elif line.startswith("["):
                            in_deps = False
                        elif in_deps and line and not line.startswith("#"):
                            count += 1
                else:
                    count += 10
            except Exception:
                count += 10
    except Exception:
        return 10

    return max(5, min(count, 300))


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
    timeout_sec = None
    if timeout_sec_str is not None:
        try:
            timeout_sec = float(timeout_sec_str)
            if not math.isfinite(timeout_sec) or timeout_sec <= 0:
                raise ValueError("RULE_TIMEOUT_SEC は正の有限値である必要があります。")
        except ValueError:
            logger.warning(
                f"RULE_TIMEOUT_SEC の指定が無効です: '{timeout_sec_str}'。デフォルト値を使用します。"
            )
            timeout_sec = None

    sorted_rules = sorted(
        rules,
        key=lambda rule: _rule_sort_key(getattr(rule, "rule_id", type(rule).__name__)),
    )
    total = len(sorted_rules)

    # 脆弱性キャッシュ設定 of 伝播用パラメータを取得
    from src.rules.B_dependencies.vuln_sources import VulnLookupService

    cache_dir = getattr(VulnLookupService._active_config, "cache_dir", None)
    cache_ttl = getattr(VulnLookupService._active_config, "cache_ttl", None)

    import multiprocessing

    mp_context = multiprocessing.get_context("spawn")

    # 実行中のルールを強制終了できるように ProcessPoolExecutor を使用
    executor = concurrent.futures.ProcessPoolExecutor(
        max_workers=1,
        initializer=_worker_initializer,
        mp_context=mp_context,
    )
    try:
        for index, rule in enumerate(sorted_rules, start=1):
            rule_id = getattr(rule, "rule_id", type(rule).__name__)
            if progress_callback is not None:
                progress_callback(index, total, rule_id)

            executed_count += 1

            # 適用するタイムアウト値を決定する
            if timeout_sec is not None:
                current_timeout = timeout_sec
            else:
                if rule_id == "B-1":
                    # B-1ルールのみ、親プロセスでのフリーズを防ぎつつ安全に推定された件数に基づいて動的タイムアウトを設定する
                    dep_count = _estimate_dependency_count_safe(target)
                    current_timeout = max(300.0, float(dep_count * 100.0))
                    logger.info(
                        f"B-1ルールのための推定依存件数: {dep_count}件。実行タイムアウトとして {current_timeout}秒 を適用します。"
                    )
                else:
                    # B-1以外のルールは一律 300秒
                    current_timeout = 300.0

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
                found = future.result(timeout=current_timeout)
                if found:
                    records.extend(found)
            except concurrent.futures.TimeoutError:
                msg = f"ルール {rule_id} の実行がタイムアウト（{current_timeout}秒）しました。"
                logger.error(msg)
                errors.append(
                    (
                        rule_id,
                        f"TimeoutError: Rule execution timed out after {current_timeout} seconds.",
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
        _cleanup_executor_processes(executor)
        executor.shutdown(wait=False)

    return records, errors, executed_count
