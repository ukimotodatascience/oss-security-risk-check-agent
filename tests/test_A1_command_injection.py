import textwrap
from pathlib import Path

import pytest

from src.models import RiskRecord, Severity
from src.rules.A_code.A1_command_injection import A1CommandInjectionRule
from src.rules.A_code.A1_3_command_injection_js_ts import (
    JsTsCommandInjectionDetector,
)
from src.rules.A_code.A1_4_command_injection_shell import ShellCommandInjectionDetector


def write_files(root: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def scan_files(root: Path, files: dict[str, str]):
    write_files(root, files)
    return A1CommandInjectionRule().evaluate(root)


def test_python_detects_interprocedural_command_builder(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.py": """
                import os

                def normalize(value):
                    return value.strip()

                def build_cmd(value):
                    clean = normalize(value)
                    return "echo " + clean

                user = input()
                cmd = build_cmd(user)
                os.system(cmd)
            """
        },
    )

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH
    assert "taint:" in (records[0].message or "")


def test_python_tracks_dict_and_attribute_values(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.py": """
                import subprocess

                class Box:
                    pass

                box = Box()
                data = {}
                data["target"] = input()
                box.cmd = "cat " + data["target"]
                subprocess.run(box.cmd, shell=True)
            """
        },
    )

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "source",
    [
        """
        import os

        def helper(user_value):
            os.system("date")

        value = input()
        helper(value)
        """,
        """
        import os
        import re

        user = input()
        if not re.fullmatch("^[A-Za-z0-9_.-]+$", user):
            raise ValueError("invalid target")
        os.system(user)
        """,
    ],
)
def test_python_ignores_safe_cases(tmp_path, source):
    records = scan_files(tmp_path, {"app.py": source})

    assert records == []


def test_python_does_not_treat_non_terminating_regex_check_as_sanitizer(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.py": """
                import os
                import re

                user = input()
                if re.match(".*", user):
                    pass
                os.system(user)
            """
        },
    )

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "filename, source",
    [
        (
            "app.js",
            """
            const cp = require("child_process");
            const cmd = req.query.cmd;
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("node:child_process");
            const run = cp.exec;
            const cmd = req.query.cmd;
            run(cmd);
            """,
        ),
        (
            "app.js",
            """
            const { spawn } = require("child_process");
            const target = req.body.target;
            spawn("sh", ["-c", "cat " + target], { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const { spawn } = require("child_process");
            const opts = { shell: true };
            const target = req.body.target;
            spawn("cat", [target], opts);
            """,
        ),
        (
            "app.js",
            """
            const target = req.query.target;
            execa.command("cat " + target);
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            result=$(grep "$1" users.txt)
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            read cmd
            eval "$cmd"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            source "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            cmd="$1"
            $cmd --version
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            bash <<< "$1"
            """,
        ),
    ],
)
def test_detects_script_command_injection_cases(tmp_path, filename, source):
    records = scan_files(tmp_path, {filename: source})

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "shelljs_import, call",
    [
        ('const { exec } = require("shelljs");', "exec(req.query.cmd);"),
        ('const sh = require("shelljs");', "sh.exec(req.query.cmd);"),
        ('import sh from "shelljs";', "sh.exec(req.query.cmd);"),
        ('import * as sh from "shelljs";', "sh.exec(req.query.cmd);"),
    ],
)
def test_js_detects_imported_shelljs_exec_with_child_process_sinks(
    tmp_path, shelljs_import, call
):
    records = scan_files(
        tmp_path,
        {
            "app.js": f"""
                const {{ spawn }} = require("child_process");
                {shelljs_import}
                {call}
            """
        },
    )

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH
    assert records[0].message == "External input reaches shell command execution helper"


@pytest.mark.parametrize(
    "detector, tree_sitter_method, filename, source",
    [
        (
            JsTsCommandInjectionDetector(),
            "_evaluate_js_ts_file_with_tree_sitter",
            "app.js",
            'execa.command("cat " + req.query.target);',
        ),
        (
            ShellCommandInjectionDetector(),
            "_evaluate_shell_file_with_tree_sitter",
            "run.sh",
            'source "$1"',
        ),
    ],
)
def test_script_detectors_merge_tree_sitter_and_fallback_findings(
    tmp_path, monkeypatch, detector, tree_sitter_method, filename, source
):
    file_path = tmp_path / filename
    file_path.write_text(source, encoding="utf-8")
    expected = RiskRecord(
        rule_id=detector.rule_id,
        category=detector.category,
        title=detector.title,
        severity=Severity.HIGH,
        file_path=filename,
        line=1,
        message="tree-sitter finding",
    )
    monkeypatch.setattr(detector, tree_sitter_method, lambda *_args: [expected])

    records = detector.evaluate(tmp_path)

    assert expected in records
    assert len(records) == 2


@pytest.mark.parametrize(
    "detector, tree_sitter_method, filename, source",
    [
        (
            JsTsCommandInjectionDetector(),
            "_evaluate_js_ts_file_with_tree_sitter",
            "app.js",
            'const { exec } = require("child_process"); exec(req.query.cmd);',
        ),
        (
            ShellCommandInjectionDetector(),
            "_evaluate_shell_file_with_tree_sitter",
            "run.sh",
            'eval "$1"',
        ),
    ],
)
def test_script_detectors_keep_fallback_only_findings_after_tree_sitter_success(
    tmp_path, monkeypatch, detector, tree_sitter_method, filename, source
):
    file_path = tmp_path / filename
    file_path.write_text(source, encoding="utf-8")
    monkeypatch.setattr(detector, tree_sitter_method, lambda *_args: [])

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "detector, tree_sitter_method, filename, source",
    [
        (
            JsTsCommandInjectionDetector(),
            "_evaluate_js_ts_file_with_tree_sitter",
            "app.js",
            'const { exec } = require("child_process"); exec(req.query.cmd);',
        ),
        (
            ShellCommandInjectionDetector(),
            "_evaluate_shell_file_with_tree_sitter",
            "run.sh",
            'eval "$1"',
        ),
    ],
)
def test_script_detectors_fall_back_when_tree_sitter_is_unavailable(
    tmp_path, monkeypatch, detector, tree_sitter_method, filename, source
):
    file_path = tmp_path / filename
    file_path.write_text(source, encoding="utf-8")
    monkeypatch.setattr(detector, tree_sitter_method, lambda *_args: None)

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "detector, tree_sitter_method, filename, source, message",
    [
        (
            JsTsCommandInjectionDetector(),
            "_evaluate_js_ts_file_with_tree_sitter",
            "app.js",
            'const { exec } = require("child_process"); exec(req.query.cmd);',
            "External input reaches child_process command execution",
        ),
        (
            ShellCommandInjectionDetector(),
            "_evaluate_shell_file_with_tree_sitter",
            "run.sh",
            'eval "$1"',
            "External input reaches shell eval",
        ),
    ],
)
def test_script_detectors_dedupe_matching_tree_sitter_and_fallback_findings(
    tmp_path, monkeypatch, detector, tree_sitter_method, filename, source, message
):
    file_path = tmp_path / filename
    file_path.write_text(source, encoding="utf-8")
    tree_sitter_record = RiskRecord(
        rule_id=detector.rule_id,
        category=detector.category,
        title=detector.title,
        severity=Severity.HIGH,
        file_path=filename,
        line=1,
        message=message,
    )
    monkeypatch.setattr(
        detector, tree_sitter_method, lambda *_args: [tree_sitter_record]
    )

    records = detector.evaluate(tmp_path)

    assert records == [tree_sitter_record]
