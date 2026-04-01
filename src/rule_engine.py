"""ルール実行。"""

from __future__ import annotations

import importlib
import inspect
import traceback
from pathlib import Path
from typing import Any, List, Sequence, Tuple

from src.models import RiskRecord


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
    rule_map = {getattr(rule, "rule_id", type(rule).__name__): rule for rule in rules}

    def run(rule_id: str) -> None:
        nonlocal executed_count
        rule = rule_map.get(rule_id)
        if rule is None:
            return
        executed_count += 1
        try:
            found = rule.evaluate(target)
            if found:
                records.extend(found)
        except Exception:
            errors.append((rule_id, traceback.format_exc()))

    # 各ルールの実行
    run("A-1")
    run("A-2")
    run("A-3")
    run("A-4")
    run("A-5")
    run("A-6")
    run("A-7")
    run("A-8")
    run("B-1")
    run("B-2")
    run("B-3")
    run("B-4")
    run("B-5")
    run("B-6")
    run("C-1")
    run("C-2")
    run("C-3")
    run("C-4")
    run("C-5")
    run("C-6")
    run("C-7")
    run("C-8")
    run("D-1")
    run("D-2")
    run("D-3")
    run("D-4")
    run("D-5")
    run("D-6")
    run("D-7")
    run("E-1")
    run("E-2")
    run("E-3")
    run("E-4")
    run("E-5")
    run("E-6")
    run("F-1")
    run("F-2")
    run("F-3")
    run("F-4")
    run("F-5")
    run("F-6")
    run("G-1")
    run("G-2")
    run("G-3")
    run("G-4")
    run("G-5")
    run("G-6")
    run("G-7")
    run("G-8")
    run("H-1")
    run("H-2")
    run("H-3")
    run("H-4")
    run("H-5")
    run("H-6")
    run("I-1")
    run("I-2")
    run("I-3")
    run("I-4")
    run("I-5")
    run("J-1")
    run("J-2")
    run("J-3")
    run("J-4")
    run("J-5")
    run("J-6")
    run("J-7")
    run("K-1")
    run("K-2")
    run("K-3")
    run("K-4")
    run("K-5")
    run("L-1")
    run("L-2")
    run("L-3")
    run("L-4")
    run("L-5")
    run("L-6")
    run("L-7")

    return records, errors, executed_count
