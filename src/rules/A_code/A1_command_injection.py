from pathlib import Path
from typing import List

from src.models import RiskRecord
from src.rules.A_code.A1_1_command_injection_common import (
    CATEGORY,
    DEFAULT_SEVERITY,
    RULE_ID,
    TITLE,
    dedupe_records,
)
from src.rules.A_code.A1_2_command_injection_python import PythonCommandInjectionDetector
from src.rules.A_code.A1_3_command_injection_js_ts import JsTsCommandInjectionDetector
from src.rules.A_code.A1_4_command_injection_shell import ShellCommandInjectionDetector


class A1CommandInjectionRule:
    """Detect external input flowing into OS command execution."""

    rule_id = RULE_ID
    category = CATEGORY
    title = TITLE
    severity = DEFAULT_SEVERITY

    def __init__(self) -> None:
        self._detectors = (
            PythonCommandInjectionDetector(),
            JsTsCommandInjectionDetector(),
            ShellCommandInjectionDetector(),
        )

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for detector in self._detectors:
            records.extend(detector.evaluate(target))
        return dedupe_records(records)
