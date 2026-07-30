"""ルール実行。"""

from __future__ import annotations

import concurrent.futures
import importlib
import inspect
import logging
import os
import traceback
from pathlib import Path
from typing import Any, Callable, List, Sequence, Tuple

from src.models import RiskRecord

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


def run_all(
    target: Path,
    rules: Sequence[Any],
    progress_callback: Callable[[int, int, str], None] | None = None,
) -> Tuple[List[RiskRecord], List[Tuple[str, str]], int]:
    """各ルールを1つずつ実行し、検知結果・失敗情報・実行数を返す。タイムアウト制御あり。"""
    records: List[RiskRecord] = []
    errors: List[Tuple[str, str]] = []
    executed_count = 0

    timeout_sec_str = os.environ.get("RULE_TIMEOUT_SEC", "30")
    try:
        timeout_sec = float(timeout_sec_str)
    except ValueError:
        logger.warning(
            f"RULE_TIMEOUT_SEC の指定が無効です: '{timeout_sec_str}'。デフォルトの 30 秒を使用します。"
        )
        timeout_sec = 30.0

    sorted_rules = sorted(
        rules,
        key=lambda rule: _rule_sort_key(getattr(rule, "rule_id", type(rule).__name__)),
    )
    total = len(sorted_rules)

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        for index, rule in enumerate(sorted_rules, start=1):
            rule_id = getattr(rule, "rule_id", type(rule).__name__)
            if progress_callback is not None:
                progress_callback(index, total, rule_id)

            executed_count += 1
            future = executor.submit(rule.evaluate, target)
            try:
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
                executor.shutdown(wait=False)
                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            except Exception:
                tb = traceback.format_exc()
                logger.exception(f"ルール {rule_id} の実行中にエラーが発生しました。")
                errors.append((rule_id, tb))
    finally:
        executor.shutdown(wait=False)

    return records, errors, executed_count
