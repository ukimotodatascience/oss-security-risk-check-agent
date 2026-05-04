from pathlib import Path

from src.models import RiskRecord
from src.rule_engine import load_all_rules, run_all


EXPECTED_RULE_IDS = {
    "A-1",
    "A-2",
    "A-3",
    "A-4",
    "A-5",
    "A-6",
    "A-7",
    "A-8",
    "B-1",
    "B-2",
    "B-3",
    "B-4",
    "B-5",
    "B-6",
    "C-1",
    "C-2",
    "C-3",
    "C-4",
    "C-5",
    "C-6",
    "C-7",
    "C-8",
    "D-1",
    "D-2",
    "D-3",
    "D-4",
    "D-5",
    "D-6",
    "D-7",
    "E-1",
    "E-2",
    "E-3",
    "E-4",
    "E-5",
    "E-6",
    "F-1",
    "F-2",
    "F-3",
    "F-4",
    "F-5",
    "F-6",
    "G-1",
    "G-2",
    "G-3",
    "G-4",
    "G-5",
    "G-6",
    "G-7",
    "G-8",
    "H-1",
    "H-2",
    "H-3",
    "H-4",
    "H-5",
    "H-6",
    "I-1",
    "I-2",
    "I-3",
    "I-4",
    "I-5",
    "J-1",
    "J-2",
    "J-3",
    "J-4",
    "J-5",
    "J-6",
    "J-7",
    "K-1",
    "K-2",
    "K-3",
    "K-4",
    "K-5",
    "L-1",
    "L-2",
    "L-3",
    "L-4",
    "L-5",
    "L-6",
    "L-7",
}


def test_load_all_rules_has_unique_expected_rule_ids():
    rules = load_all_rules(Path.cwd())
    rule_ids = [rule.rule_id for rule in rules]

    assert len(rule_ids) == len(set(rule_ids))
    assert set(rule_ids) == EXPECTED_RULE_IDS


def test_run_all_executes_all_loaded_rules(tmp_path):
    rules = load_all_rules(Path.cwd())

    records, errors, executed_count = run_all(tmp_path, rules)

    assert executed_count == len(EXPECTED_RULE_IDS)
    assert errors == []
    assert all(isinstance(record, RiskRecord) for record in records)
