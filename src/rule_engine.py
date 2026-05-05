"""ルール実行。"""

from __future__ import annotations

import importlib
import inspect
import traceback
from pathlib import Path
from typing import Any, List, Sequence, Tuple

from src.models import RiskRecord


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
    target: Path, rules: Sequence[Any]
) -> Tuple[List[RiskRecord], List[Tuple[str, str]], int]:
    """各ルールを1つずつ実行し、検知結果・失敗情報・実行数を返す。"""
    records: List[RiskRecord] = []
    errors: List[Tuple[str, str]] = []
    executed_count = 0

    def run(rule: Any) -> None:
        nonlocal executed_count
        rule_id = getattr(rule, "rule_id", type(rule).__name__)
        executed_count += 1
        try:
            found = rule.evaluate(target)
            if found:
                records.extend(found)
        except Exception:
            errors.append((rule_id, traceback.format_exc()))

    for rule in sorted(
        rules,
        key=lambda rule: _rule_sort_key(getattr(rule, "rule_id", type(rule).__name__)),
    ):
        run(rule)

    return records, errors, executed_count
