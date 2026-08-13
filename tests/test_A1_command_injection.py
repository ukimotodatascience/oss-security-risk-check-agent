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
        ('const run = require("shelljs").exec;', "run(req.query.cmd);"),
        ('import sh from "shelljs";', "sh.exec(req.query.cmd);"),
        ('import * as sh from "shelljs";', "sh.exec(req.query.cmd);"),
        ('import sh, { exec as run } from "shelljs";', "run(req.query.cmd);"),
        ('import sh, * as shell from "shelljs";', "shell.exec(req.query.cmd);"),
        ('import { default as sh } from "shelljs";', "sh.exec(req.query.cmd);"),
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


def test_js_dedupes_shelljs_module_exec_across_ast_and_fallback(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                const sh = require("shelljs");
                sh.exec(req.query.cmd);
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_collects_static_shelljs_imports_before_calls(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { spawn } from "child_process";
                exec(req.query.cmd);
                import { exec } from "shelljs";
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_collects_top_level_shelljs_require_before_calls(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                const { spawn } = require("child_process");
                function handler(req) { exec(req.query.cmd); }
                const { exec } = require("shelljs");
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_does_not_match_shelljs_alias_as_object_method(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { exec as run } from "shelljs";
                db.run(req.query.cmd);
            """
        },
    )

    assert records == []


def test_js_fallback_ignores_backticks_inside_strings(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    file_path = tmp_path / "app.js"
    file_path.write_text(
        """const marker = "`";
const { spawn } = require("child_process");
const { exec } = require("shelljs");
exec(req.query.cmd);
""",
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_detects_optional_chained_shelljs_exec(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                const { spawn } = require("child_process");
                const sh = require("shelljs");
                sh?.exec(req.query.cmd);
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_detects_defaulted_shelljs_destructuring(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                const { spawn } = require("child_process");
                const { exec = fallbackExec } = require("shelljs");
                exec(req.query.cmd);
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_ignores_shadowed_shelljs_alias(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { exec as run } from "shelljs";
                function handler(req) {
                    const run = value => value;
                    run(req.query.cmd);
                }
            """
        },
    )

    assert records == []


def test_js_ignores_shelljs_import_inside_block_comment(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                /*
                import { exec as run } from "shelljs";
                */
                run(req.query.cmd);
            """
        },
    )

    assert records == []


def test_js_ignores_shadowed_shelljs_module_alias(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import sh from "shelljs";
                function handler(req) {
                    const sh = safeHelper;
                    sh.exec(req.query.cmd);
                }
            """
        },
    )

    assert records == []


def test_js_detects_function_local_shelljs_binding(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                const { spawn } = require("child_process");
                function handler(req) {
                    const exec = require("shelljs").exec;
                    exec(req.query.cmd);
                }
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_dedupes_function_first_shelljs_call(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import sh from "shelljs";
                function handler(req) {
                    sh.exec(req.query.cmd);
                }
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_ignores_shelljs_alias_shadowed_by_parameter(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { exec as run } from "shelljs";
                function handler(run, req) {
                    run(req.query.cmd);
                }
            """
        },
    )

    assert records == []


@pytest.mark.parametrize("parameters", ["run", "(run, req)"])
def test_js_ignores_shelljs_alias_shadowed_by_arrow_parameter(tmp_path, parameters):
    records = scan_files(
        tmp_path,
        {
            "app.js": f"""
                import {{ exec as run }} from "shelljs";
                const handler = {parameters} => {{
                    run(req.query.cmd);
                }};
            """
        },
    )

    assert records == []


def test_js_fallback_updates_template_state_on_slash_comment_line(
    tmp_path, monkeypatch
):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    file_path = tmp_path / "app.js"
    file_path.write_text(
        """const example = `
// `;
const { spawn } = require("child_process");
const { exec } = require("shelljs");
exec(req.query.cmd);
""",
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_ignores_function_string_with_shelljs_declaration(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                function handler(req) {
                    const example = "const { exec: run } = require('shelljs')";
                    run(req.query.cmd);
                }
            """
        },
    )

    assert records == []


def test_js_keeps_parameter_scope_across_object_literal(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { exec as run } from "shelljs";
                function handler(run, req) {
                    const options = { safe: true };
                    run(req.query.cmd);
                }
            """
        },
    )

    assert records == []


def test_js_fallback_updates_block_comment_state_on_slash_comment_line(
    tmp_path, monkeypatch
):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    file_path = tmp_path / "app.js"
    file_path.write_text(
        """/* comment
// */
const { spawn } = require("child_process");
const { exec } = require("shelljs");
exec(req.query.cmd);
""",
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_detects_function_binding_after_inline_comment(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    file_path = tmp_path / "app.js"
    file_path.write_text(
        """const { spawn } = require("child_process");
function handler(req) { // comment
    const exec = require("shelljs").exec;
    exec(req.query.cmd);
}
""",
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_ignores_shelljs_alias_shadowed_by_catch_parameter(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { exec as run } from "shelljs";
                try {
                    riskyOperation();
                } catch (run) {
                    run(req.query.cmd);
                }
            """
        },
    )

    assert records == []


@pytest.mark.parametrize(
    "child_process_import, call",
    [
        ('import * as cp from "node:child_process";', "cp.exec(req.query.cmd);"),
        ('import cp from "child_process";', "cp.exec(req.query.cmd);"),
        ("", 'require("child_process").exec(req.query.cmd);'),
    ],
)
def test_js_detects_child_process_module_calls(tmp_path, child_process_import, call):
    records = scan_files(
        tmp_path,
        {"app.js": f"{child_process_import}\n{call}\n"},
    )

    assert len(records) == 1
    assert (
        records[0].message == "External input reaches child_process command execution"
    )


def test_js_detects_multiline_shelljs_named_import(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { spawn } from "child_process";
                import {
                    exec as run
                } from "shelljs";
                run(req.query.cmd);
            """
        },
    )

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_fallback_detects_arrow_local_shelljs_binding(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    file_path = tmp_path / "app.js"
    file_path.write_text(
        """const { spawn } = require("child_process");
const handler = req => {
    const exec = require("shelljs").exec;
    exec(req.query.cmd);
};
""",
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_ts_ignores_shelljs_alias_shadowed_by_typed_parameter(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.ts": """
                import { exec as run } from "shelljs";
                function handler(run: Runner, req: Req) {
                    run(req.query.cmd);
                }
            """
        },
    )

    assert records == []


def test_js_handles_parameterless_function_before_shelljs_call(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": 'import sh from "shelljs"; function helper() {} sh.exec(req.query.cmd);'
        },
    )

    assert len(records) == 1


@pytest.mark.parametrize(
    "child_process_import",
    [
        'import cp, { spawn } from "node:child_process";',
        'import cp, * as child from "node:child_process";',
    ],
)
def test_js_detects_composite_child_process_module_import(
    tmp_path, child_process_import
):
    records = scan_files(
        tmp_path,
        {"app.js": f"{child_process_import}\ncp.exec(req.query.cmd);"},
    )

    assert len(records) == 1


def test_js_fallback_ignores_backtick_inside_regex_literal(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(
        'const marker = /`/;\nimport { spawn } from "child_process";\n'
        'import { exec } from "shelljs";\nexec(req.query.cmd);\n',
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


def test_js_fallback_detects_optional_chained_child_process_call(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(
        'import * as cp from "node:child_process";\ncp?.exec(req.query.cmd);\n',
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


def test_js_fallback_ignores_backtick_in_regex_after_return(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(
        "function marker() { return /`/; }\n"
        'import { spawn } from "child_process";\n'
        'import { exec } from "shelljs";\nexec(req.query.cmd);\n',
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


def test_js_detects_direct_shelljs_require_exec(tmp_path):
    records = scan_files(
        tmp_path,
        {"app.js": 'require("shelljs").exec(req.query.cmd);'},
    )

    assert len(records) == 1


@pytest.mark.parametrize(
    "parameters",
    ["{ run }, req", "[run], req", "...run"],
)
def test_js_ignores_shelljs_alias_shadowed_by_destructured_parameter(
    tmp_path, parameters
):
    records = scan_files(
        tmp_path,
        {
            "app.js": f'import {{ exec as run }} from "shelljs"; function handler({parameters}) {{ run(req.query.cmd); }}'
        },
    )

    assert records == []


def test_js_ignores_shelljs_alias_shadowed_by_hoisted_function(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": 'import { exec as run } from "shelljs"; function handler(req) { run(req.query.cmd); function run(value) { return value; } }'
        },
    )

    assert records == []


def test_js_detects_shelljs_alias_after_completed_inner_shadow(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": 'import sh from "shelljs"; function handler(req) { if (false) { const sh = safe; } sh.exec(req.query.cmd); }'
        },
    )

    assert len(records) == 1


@pytest.mark.parametrize(
    "parameters",
    ["callback = run, req", "{ run: callback }, req", "callback: Runner, req"],
)
def test_js_detects_shelljs_alias_referenced_but_not_bound_in_parameter(
    tmp_path, parameters
):
    records = scan_files(
        tmp_path,
        {
            "app.ts": f'import {{ exec as run }} from "shelljs"; function handler({parameters}) {{ run(req.query.cmd); }}'
        },
    )

    assert len(records) == 1


def test_js_fallback_splits_same_line_shelljs_statements(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(
        'const sh = require("shelljs"); sh.exec(req.query.cmd);', encoding="utf-8"
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


@pytest.mark.parametrize(
    "example",
    ['const example = "run(req.query.cmd)";', "const value = 1; // run(req.query.cmd)"],
)
def test_js_ignores_shelljs_calls_in_noncode_text(tmp_path, example):
    records = scan_files(
        tmp_path,
        {"app.js": f'import {{ exec as run }} from "shelljs"; {example}'},
    )

    assert records == []


@pytest.mark.parametrize("disable_tree_sitter", [False, True])
def test_js_detects_direct_child_process_spawn(
    tmp_path, monkeypatch, disable_tree_sitter
):
    detector = JsTsCommandInjectionDetector()
    if disable_tree_sitter:
        monkeypatch.setattr(
            detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
        )
    (tmp_path / "app.js").write_text(
        'require("child_process").spawn(req.query.cmd, [], { shell: true });',
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


@pytest.mark.parametrize(
    "call",
    [
        "execa.command(`echo ${req.query.cmd}`);",
        'require("shelljs").exec(`echo ${req.query.cmd}`);',
    ],
)
def test_js_fallback_preserves_taint_in_template_interpolation(
    tmp_path, monkeypatch, call
):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(call, encoding="utf-8")

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


@pytest.mark.parametrize(
    "call",
    [
        'require ("shelljs").exec(req.query.cmd);',
        'require( "shelljs" ).exec(req.query.cmd);',
    ],
)
def test_js_detects_direct_shelljs_require_with_whitespace(tmp_path, call):
    records = scan_files(tmp_path, {"app.js": call})

    assert len(records) == 1


@pytest.mark.parametrize("api", ["exec", "execSync"])
def test_js_fallback_detects_optional_direct_child_process_exec(
    tmp_path, monkeypatch, api
):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(
        f'require("child_process")?.{api}(req.query.cmd);', encoding="utf-8"
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


def test_js_detects_shelljs_alias_after_inner_function_declaration(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": 'import { exec as run } from "shelljs"; function handler(req) { if (false) { function run() {} } run(req.query.cmd); }'
        },
    )

    assert len(records) == 1


def test_js_fallback_preserves_nested_template_interpolation_taint(
    tmp_path, monkeypatch
):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(
        'require("shelljs").exec(`echo ${{ value: req.query.cmd }.value}`);',
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


def test_js_detects_commonjs_shelljs_binding_with_require_whitespace(tmp_path):
    records = scan_files(
        tmp_path,
        {"app.js": 'const sh = require ("shelljs"); sh.exec(req.query.cmd);'},
    )

    assert len(records) == 1


def test_js_fallback_ignores_brace_in_interpolation_string(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    (tmp_path / "app.js").write_text(
        'require("shelljs").exec(`echo ${"}" + req.query.cmd}`);',
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1


@pytest.mark.parametrize(
    "declaration", ["const { run } = helpers;", "const [run] = helpers;"]
)
def test_js_ignores_shelljs_alias_shadowed_by_local_destructuring(
    tmp_path, declaration
):
    records = scan_files(
        tmp_path,
        {
            "app.js": f'import {{ exec as run }} from "shelljs"; function handler(req) {{ {declaration} run(req.query.cmd); }}'
        },
    )

    assert records == []


def test_js_does_not_leak_local_shelljs_binding_without_top_level_name(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": 'function setup() { const run = require("shelljs").exec; } run(req.query.cmd);'
        },
    )

    assert records == []


def test_js_detects_shelljs_alias_after_independent_lexical_block(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": 'import sh from "shelljs"; function f(req) { { const sh = safe; } sh.exec(req.query.cmd); }'
        },
    )

    assert len(records) == 1


def test_js_detects_child_process_binding_with_require_whitespace(tmp_path):
    records = scan_files(
        tmp_path,
        {"app.js": 'const cp = require ("child_process"); cp.exec(req.query.cmd);'},
    )

    assert len(records) == 1


def test_js_ignores_shelljs_module_alias_shadowed_by_method_parameter(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": 'import sh from "shelljs"; class C { method(sh, req) { sh.exec(req.query.cmd); } }'
        },
    )

    assert records == []


def test_js_does_not_leak_local_shelljs_binding_to_top_level(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                function helper() {
                    const run = require("shelljs").exec;
                }
                function run(value) { return value; }
                run(req.query.cmd);
            """
        },
    )

    assert records == []


def test_js_ignores_shelljs_import_examples_in_strings(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                import { spawn } from "child_process";
                const example = "import { exec as run } from 'shelljs'";
                run(req.query.cmd);
            """
        },
    )

    assert records == []


@pytest.mark.parametrize(
    "example",
    [
        "\"const { exec: run } = require('shelljs')\"",
        '`\nimport { exec as run } from "shelljs"\n`',
    ],
)
def test_js_ignores_shelljs_declaration_examples(tmp_path, example):
    records = scan_files(
        tmp_path,
        {
            "app.js": f"""
                import {{ spawn }} from "child_process";
                const example = {example};
                run(req.query.cmd);
            """
        },
    )

    assert records == []


def test_ts_fallback_detects_shelljs_import_equals_with_child_process_sinks(
    tmp_path, monkeypatch
):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    file_path = tmp_path / "app.ts"
    file_path.write_text(
        textwrap.dedent(
            """
            import sh = require("shelljs");
            import { spawn } from "child_process";
            sh.exec(req.query.cmd);
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
    assert records[0].message == "External input reaches shell command execution helper"


def test_js_fallback_parses_semicolonless_imports_independently(tmp_path, monkeypatch):
    detector = JsTsCommandInjectionDetector()
    monkeypatch.setattr(
        detector, "_evaluate_js_ts_file_with_tree_sitter", lambda *_args: None
    )
    file_path = tmp_path / "app.js"
    file_path.write_text(
        textwrap.dedent(
            """
            import { spawn } from "child_process"
            import sh from "shelljs"
            sh.exec(req.query.cmd)
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )

    records = detector.evaluate(tmp_path)

    assert len(records) == 1
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
