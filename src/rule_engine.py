"""ルール実行。"""

from __future__ import annotations

import atexit
import concurrent.futures
import copyreg
import importlib
import multiprocessing
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


def _worker_initializer(
    level_name: str | None = None, log_file: Path | None = None
) -> None:
    """プロセスプールのワーカープロセス初期化時に新しいプロセスグループを作成し、WindowsではJob Objectに登録する。"""
    import os

    if hasattr(os, "setpgrp"):
        try:
            os.setpgrp()
        except Exception:
            pass

    _setup_windows_job_object()

    if level_name is not None:
        try:
            from src.logger import setup_logging
            import src.logger

            src.logger._logging_initialized = False
            setup_logging(level=level_name, log_file=log_file)
        except Exception:
            pass


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
        stack = [target]
        while stack and total_entries_checked <= 100:
            current_dir = stack.pop()
            try:
                for p in current_dir.iterdir():
                    total_entries_checked += 1
                    if total_entries_checked > 100:
                        break

                    if p.is_file() and (
                        p.name in dep_names or p.name.startswith("requirements")
                    ):
                        candidates.append(p)
                    elif (
                        p.is_dir()
                        and not p.is_symlink()
                        and p.name
                        not in {
                            ".git",
                            "node_modules",
                            ".venv",
                            "venv",
                            "__pycache__",
                        }
                    ):
                        stack.append(p)
            except Exception:
                pass

        # 候補ファイル数が 20 件を超えている（走査しきれなかった）場合、
        # 依存関係が走査漏れになっている可能性が高いため、安全に最大件数 300 を返す
        if len(candidates) > 20:
            return 300

        for filepath in candidates:
            if files_scanned >= 20:
                break

            try:
                stat = filepath.stat()
                # 1ファイルあたり 500KB 上限
                if stat.st_size > 500 * 1024:
                    # 500KBを超える巨大なマニフェストファイルが存在する場合、実際の依存関係数が推定値を大幅に
                    # 上回るリスクがあるため、安全のために最大件数である 300 件を返してフェイルセーフ上限予算を適用する。
                    return 300

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

    # 走査が途中で打ち切られた（エントリ数が100を超えた）場合、
    # 依存関係が走査漏れになっている可能性が高いため、安全に最大件数 300 を返す
    if total_entries_checked > 100:
        return 300

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


_executor_pool: List[concurrent.futures.ProcessPoolExecutor] = []
_executor_pool_lock = threading.Lock()
_busy_executors: set[concurrent.futures.ProcessPoolExecutor] = set()
_global_executor: Any = None


def _get_logging_config() -> Tuple[str, Path | None]:
    root = logging.getLogger()
    level_name = logging.getLevelName(root.getEffectiveLevel())
    log_file: Path | None = None
    for h in root.handlers:
        if isinstance(h, logging.FileHandler):
            log_file = Path(h.baseFilename)
            break
    return level_name, log_file


def _get_global_executor() -> concurrent.futures.ProcessPoolExecutor:
    global _global_executor
    with _executor_pool_lock:
        available = None
        for executor in _executor_pool:
            if executor not in _busy_executors:
                available = executor
                break

        if available is None:
            mp_context = multiprocessing.get_context("spawn")
            level_name, log_file = _get_logging_config()
            available = concurrent.futures.ProcessPoolExecutor(
                max_workers=1,
                initializer=_worker_initializer,
                initargs=(level_name, log_file),
                mp_context=mp_context,
            )
            _executor_pool.append(available)

        _busy_executors.add(available)
        _global_executor = available
        return available


def _release_executor(executor: concurrent.futures.ProcessPoolExecutor) -> None:
    with _executor_pool_lock:
        if executor in _busy_executors:
            _busy_executors.remove(executor)


def _discard_executor(executor: concurrent.futures.ProcessPoolExecutor) -> None:
    with _executor_pool_lock:
        if executor in _busy_executors:
            _busy_executors.remove(executor)
        if executor in _executor_pool:
            _executor_pool.remove(executor)
        try:
            _cleanup_executor_processes(executor)
            executor.shutdown(wait=False)
        except Exception:
            pass


def _reset_global_executor() -> None:
    global _global_executor
    with _executor_pool_lock:
        for executor in _executor_pool:
            try:
                _cleanup_executor_processes(executor)
                executor.shutdown(wait=False)
            except Exception:
                pass
        _executor_pool.clear()
        _busy_executors.clear()
    _global_executor = None


@atexit.register
def _cleanup_global_executor() -> None:
    _reset_global_executor()


def _evaluate_rule_in_process(
    rule_bytes: bytes,
    target: Path,
    cache_dir: Path | None,
    cache_ttl: int | None,
) -> Tuple[bool, List[RiskRecord], str | None]:
    """子プロセス内でルールを評価し、(成功フラグ, 検知レコード, 例外詳細) を返す。"""
    import copyreg
    import pickle
    import threading
    import traceback
    from src.rules.B_dependencies.vuln_sources import VulnLookupService

    # 子プロセス側でも threading.local の pickle を登録
    copyreg.pickle(threading.local, _pickle_local)

    try:
        rule = pickle.loads(rule_bytes)
        with VulnLookupService.use_config(cache_dir, cache_ttl):
            records = rule.evaluate(target)
        return True, records, None
    except BaseException as e:
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        return False, [], tb


_run_all_lock = threading.Lock()
_tracked_env_vars = [
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NVD_API_KEY",
    "OSV_API_KEY",
    "VULN_API_TIMEOUT_SEC",
    "VULN_MAX_RETRIES",
    "VULN_PROVIDER_ORDER",
    "RULE_TIMEOUT_SEC",
    "VULN_ENABLE_FALLBACK",
]
_last_tracked_env_values: dict[str, str | None] = {}


def _evaluate_rule_thread(
    rule_id: str,
    rule_bytes: bytes,
    target: Path,
    cache_dir: Path | None,
    cache_ttl: int | None,
    timeout_sec: float | None,
) -> Tuple[str, List[RiskRecord], str | None, int, List[Tuple[int, str]]]:
    """1つのルールを個別のスレッドおよび個別の一時的 ProcessPoolExecutor で評価する。"""
    records: List[RiskRecord] = []
    error_tb: str | None = None
    executed_count = 1
    thread_logs: List[Tuple[int, str]] = []

    executor = _get_global_executor()
    need_discard = False

    try:
        # 1. 適用するタイムアウト値を決定する
        current_timeout = 300.0
        if timeout_sec is not None:
            current_timeout = timeout_sec
        else:
            if rule_id == "B-1":
                dep_count_fallback = False
                try:
                    future_count = executor.submit(
                        _estimate_dependency_count_safe, target
                    )
                    dep_count = future_count.result(timeout=5.0)
                except (concurrent.futures.TimeoutError, TimeoutError) as e:
                    dep_count = 300
                    dep_count_fallback = True
                    thread_logs.append(
                        (
                            logging.WARNING,
                            f"B-1の依存件数推定が 5.0 秒以内に完了しなかったか、エラーが発生したため、安全のために最大件数の 300 件としてフォールバックします: {e}",
                        )
                    )
                    if not future_count.done():
                        _discard_executor(executor)
                        executor = _get_global_executor()
                except Exception as e:
                    dep_count = 300
                    dep_count_fallback = True
                    thread_logs.append(
                        (
                            logging.WARNING,
                            f"B-1の依存件数推定中に例外が発生したため、最大件数の 300 件としてフォールバックします: {e}",
                        )
                    )
                    _discard_executor(executor)
                    executor = _get_global_executor()

                try:
                    api_timeout = float(os.environ.get("VULN_API_TIMEOUT_SEC", "10.0"))
                except ValueError:
                    api_timeout = 10.0
                try:
                    max_retries = int(os.environ.get("VULN_MAX_RETRIES", "3"))
                except ValueError:
                    max_retries = 3

                provider_str = os.environ.get("VULN_PROVIDER_ORDER", "nvd,osv,ghsa")
                providers = [p.strip() for p in provider_str.split(",") if p.strip()]
                provider_count = max(1, len(providers))

                attempts = 1 + max(0, max_retries)
                backoff_total = 0.0
                for r in range(max(0, max_retries)):
                    backoff_total += min(0.5 * (2**r), 2.0)

                sec_per_dep = max(
                    100.0,
                    float(provider_count)
                    * (attempts * api_timeout + backoff_total)
                    * 1.5,
                )

                if dep_count_fallback:
                    current_timeout = 300.0
                    thread_logs.append(
                        (
                            logging.WARNING,
                            f"B-1の依存件数推定が失敗したため、安全のために実行タイムアウトにフェイルセーフ上限 {current_timeout}秒 を適用します。",
                        )
                    )
                elif dep_count >= 300:
                    current_timeout = max(54000.0, float(dep_count * sec_per_dep))
                    thread_logs.append(
                        (
                            logging.INFO,
                            f"B-1の推定依存件数が上限（{dep_count}件）に達したため、有限のフェイルセーフ上限として実行タイムアウト {current_timeout}秒 を適用します。",
                        )
                    )
                else:
                    current_timeout = max(300.0, float(dep_count * sec_per_dep))
                    thread_logs.append(
                        (
                            logging.INFO,
                            f"B-1ルールのための推定依存件数: {dep_count}件。実行タイムアウトとして {current_timeout}秒 を適用します。",
                        )
                    )
            else:
                current_timeout = 300.0

        # 2. ルール評価の実行
        future = executor.submit(
            _evaluate_rule_in_process,
            rule_bytes,
            target,
            cache_dir,
            cache_ttl,
        )

        try:
            success, found, tb = future.result(timeout=current_timeout)
            if success:
                if found:
                    records.extend(found)
            else:
                thread_logs.append(
                    (
                        logging.ERROR,
                        f"ルール {rule_id} の実行中にエラーが発生しました。\n{tb}",
                    )
                )
                error_tb = tb
        except (concurrent.futures.TimeoutError, TimeoutError):
            msg = f"ルール {rule_id} の実行がタイムアウト（{current_timeout}秒）しました。"
            thread_logs.append((logging.ERROR, msg))
            error_tb = f"TimeoutError: Rule execution timed out after {current_timeout} seconds."
            need_discard = True
        except (concurrent.futures.process.BrokenProcessPool, BrokenPipeError):
            thread_logs.append(
                (
                    logging.ERROR,
                    f"ルール {rule_id} の実行プロセスがクラッシュ（BrokenProcessPool）しました。",
                )
            )
            error_tb = "BrokenProcessPool: Subprocess terminated unexpectedly."
            need_discard = True
        except Exception as e:
            tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
            thread_logs.append(
                (
                    logging.ERROR,
                    f"ルール {rule_id} の実行中にエラーが発生しました。\n{tb}",
                )
            )
            error_tb = tb
    except Exception as e:
        tb = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        thread_logs.append((logging.ERROR, f"スレッド実行で例外が発生しました。\n{tb}"))
        error_tb = tb
    finally:
        if need_discard:
            _discard_executor(executor)
        else:
            _release_executor(executor)

    return rule_id, records, error_tb, executed_count, thread_logs


def run_all(
    target: Path,
    rules: Sequence[Any],
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> Tuple[List[RiskRecord], List[Tuple[str, str]], int]:
    """各ルールを並列で実行し、検知結果・失敗情報・実行数を返す。各ルールは独立したプロセスとタイムアウト制御を持つ。"""
    with _run_all_lock:
        global _last_tracked_env_values
        env_changed = False
        current_env_values = {}
        for var in _tracked_env_vars:
            val = os.environ.get(var)
            current_env_values[var] = val
            if val != _last_tracked_env_values.get(var):
                env_changed = True

        if env_changed:
            _reset_global_executor()
            _last_tracked_env_values = current_env_values

        records: List[RiskRecord] = []
        errors: List[Tuple[str, str]] = []
        executed_count = 0

        timeout_sec_str = os.environ.get("RULE_TIMEOUT_SEC")
        timeout_sec = None
        if timeout_sec_str is not None:
            try:
                timeout_sec = float(timeout_sec_str)
                if not math.isfinite(timeout_sec) or timeout_sec <= 0:
                    raise ValueError(
                        "RULE_TIMEOUT_SEC は正の有限値である必要があります。"
                    )
            except ValueError:
                logger.warning(
                    f"RULE_TIMEOUT_SEC の指定が無効です: '{timeout_sec_str}'。デフォルト値を使用します。"
                )
                timeout_sec = None

        sorted_rules = sorted(
            rules,
            key=lambda rule: _rule_sort_key(
                getattr(rule, "rule_id", type(rule).__name__)
            ),
        )
        total = len(sorted_rules)

        from src.rules.B_dependencies.vuln_sources import VulnLookupService

        cache_dir = getattr(VulnLookupService._active_config, "cache_dir", None)
        cache_ttl = getattr(VulnLookupService._active_config, "cache_ttl", None)

        completed_count = 0
        callback_lock = threading.Lock()

        def _run_callback(rule_id: str) -> None:
            nonlocal completed_count
            if progress_callback is None:
                return
            with callback_lock:
                completed_count += 1
                progress_callback(completed_count, total, rule_id)

        thread_executor = concurrent.futures.ThreadPoolExecutor()
        try:
            if progress_callback is not None and sorted_rules:
                first_rule_id = getattr(
                    sorted_rules[0], "rule_id", type(sorted_rules[0]).__name__
                )
                progress_callback(0, total, first_rule_id)

            futures = []
            for index, rule in enumerate(sorted_rules, start=1):
                rule_id = getattr(rule, "rule_id", type(rule).__name__)

                try:
                    rule_bytes = pickle.dumps(rule)
                    futures.append(
                        thread_executor.submit(
                            _evaluate_rule_thread,
                            rule_id,
                            rule_bytes,
                            target,
                            cache_dir,
                            cache_ttl,
                            timeout_sec,
                        )
                    )
                except Exception as e:
                    tb = "".join(
                        traceback.format_exception(type(e), e, e.__traceback__)
                    )
                    errors.append((rule_id, tb))
                    executed_count += 1
                    _run_callback(rule_id)

            records_by_rule: dict[str, List[RiskRecord]] = {}
            for future in concurrent.futures.as_completed(futures):
                try:
                    rule_id, found_records, error_tb, count, thread_logs = (
                        future.result()
                    )
                    # ログメッセージをメインスレッド側で実際に出力
                    for level, msg in thread_logs:
                        logger.log(level, msg)

                    executed_count += count
                    if found_records:
                        records_by_rule[rule_id] = found_records
                    if error_tb:
                        errors.append((rule_id, error_tb))
                    _run_callback(rule_id)
                except Exception as e:
                    tb = "".join(
                        traceback.format_exception(type(e), e, e.__traceback__)
                    )
                    logger.exception("スレッド実行中に未予期のエラーが発生しました。")
                    errors.append(("unknown", tb))

            # ルールの自然な順序（sorted_rulesの順）で結果レコードを結合
            for rule in sorted_rules:
                r_id = getattr(rule, "rule_id", type(rule).__name__)
                if r_id in records_by_rule:
                    records.extend(records_by_rule[r_id])
        except BaseException:
            _reset_global_executor()
            raise
        finally:
            thread_executor.shutdown(wait=False)

        errors.sort(key=lambda x: _rule_sort_key(x[0]))

        return records, errors, executed_count
