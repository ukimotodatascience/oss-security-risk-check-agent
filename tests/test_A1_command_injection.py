import textwrap
from pathlib import Path

import pytest

from src.models import Severity
from src.rules.A_code.A1_command_injection import A1CommandInjectionRule


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
            "app.js",
            """
            const { exec } = require("shelljs");
            const { spawn } = require("child_process");
            exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process"); const proc = require("node:child_process"); proc.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            import cp from "child_process"; import proc from "node:child_process"; proc.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            async function f(){ const one=await import("child_process"); const two=await import("node:child_process"); two.exec(req.query.cmd); }
            """,
        ),
        (
            "app.js",
            """
            async function f(){ const { spawn } = await import("child_process"); const { exec } = await import("node:child_process"); exec(req.query.cmd); }
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            (cp).exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            require("child_process").exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            let proc;
            proc = require("child_process");
            proc.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const shell = require("shelljs");
            shell.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            import shell from "shelljs";
            shell.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            import * as shell from "shelljs";
            shell.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            proc.exec(req.query.cmd); import * as proc from "node:child_process";
            """,
        ),
        (
            "app.js",
            """
            const { spawn } = require("child_process");
            const target = req.query.target;
            spawn("cat", [target.replace(/\\//g, "")], { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const { spawn } = require("child_process");
            const target = req.query.target;
            spawn("cat", [target.replace(/\\)/g, "")], { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const { spawn } = require("child_process");
            const target = req.query.target;
            spawn("cat", [target.replace(/[/)]/g, "")], { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            cp.exec([.../[)]/.source, req.query.cmd].join(""));
            """,
        ),
        (
            "app.js",
            """
            const { spawn } = require("child_process");
            const target = req.query.target;
            spawn("cat", [target, (() => /\\//.test(target))()], { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const { spawn } = require("child_process");
            const target = req.query.target;
            spawn("cat", [target], /* comment
            still // comment */ { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            /* this is a long inline comment */ cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            async function f(){ await /\\//.test(x); cp.exec(req.query.cmd); }
            """,
        ),
        (
            "app.js",
            """
            const { exec } = require("child_process")
            const safe = 1
            const cmd = req.query.cmd
            exec(cmd)
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            if (ok) /\\//.test(value); cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            switch (type) { case /foo/.test(x): cp.exec(req.query.cmd); }
            """,
        ),
        (
            "app.js",
            """
            const run = require("child_process").exec;
            run(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const cmd = `let ${req.query.cmd}`;
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const cmd = "let " + req.query.cmd;
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            import { spawn } from "child_process";
            exec(req.query.cmd);
            spawn(req.query.cmd, { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            if (ok) foo(); else /\\//.test(value); cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            if (value instanceof /\\//.constructor) {};
            cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const cmd = (() => { const value = req.query.cmd; return value; })();
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const z = x / /\\//.test(y);
            cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            function f() { const cmd = req.query.cmd; cp.exec(cmd); }
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            let cmd; cmd = req.query.cmd; cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const f = () => { const cmd = req.query.cmd; cp.exec(cmd); };
            """,
        ),
        (
            "app.js",
            """
            import childProcess from "node:child_process";
            childProcess.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            import childProcess, { spawn } from "node:child_process";
            childProcess.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            cp?.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const holder = {};
            holder.cmd = req.query.cmd;
            cp.exec(holder.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            let cmd = "safe";
            cmd += req.query.cmd;
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const safe = 1, cmd = req.query.cmd;
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            import childProcess, * as childProcessNS from "node:child_process";
            childProcess.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            import childProcess, * as childProcessNS from "node:child_process";
            childProcessNS.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const { spawn: exec } = cp;
            exec(req.query.cmd, { shell: true });
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const { exec: run } = cp;
            run(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const holder = {};
            holder["cmd"] = req.query.cmd;
            cp.exec(holder["cmd"]);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const [cmd] = [req.query.cmd];
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const matches = [.../\\//g[Symbol.matchAll](value)];
            cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const { spawn: exec } = cp;
            cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            for (const match of /\\//g[Symbol.matchAll](value)) {};
            const cp = require("child_process");
            cp.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const proc = await import("node:child_process");
            proc.exec(req.query.cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const { cmd = req.query.cmd } = {};
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const { cmd = (0, req.query.cmd) } = {};
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const [cmd = (0, req.query.cmd)] = [];
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const [safe, cmd] = [/a,b/, req.query.cmd];
            cp.exec(cmd);
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
        (
            "run.sh",
            """
            #!/bin/sh
            eval 2>&1 "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            eval &>/dev/null "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            eval <(echo safe | cat) "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            sh -c "$(echo safe | cat) $1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            printf '%s' "$1" | eval "$(cat)"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            eval ${safe/;/x} "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            xargs 2>&1 sh -c "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            xargs &>/tmp/out sh -c "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            eval 'safe\\'; eval "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            xargs -I 'a;b' sh -c "$1"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            find . -name 'a|b' -exec sh -c "$1" \\;
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            env CMD="$1" sh -c "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            env -i CMD="$1" sh -c "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            env -u PATH CMD="$1" sh -c "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            export CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            declare CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            local CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            typeset CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            readonly CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            echo ok; CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            true && CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "run.sh",
            """
            #!/bin/sh
            false || CMD="$1"; eval "$CMD"
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const [cmd = req.query.cmd] = [];
            cp.exec(cmd);
            """,
        ),
        (
            "app.js",
            """
            const cp = require("child_process");
            const $cmd = req.query.cmd;
            cp.exec($cmd);
            """,
        ),
    ],
)
def test_detects_script_command_injection_cases(tmp_path, filename, source):
    records = scan_files(tmp_path, {filename: source})

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


def test_js_ignores_safe_cases(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                const cp = require("child_process");
                const x = "foo\\
                ";
                // cp.exec(req.query.cmd);
            """,
            "app2.js": """
                const cp = require("child_process");
                const cmd = `foo ${
                  // cp.exec(req.query.cmd);
                  "safe"
                }`;
            """,
            "app3.js": """
                import { spawn } from "child_process";
                const cp = worker;
                cp.exec(req.query.cmd);
            """,
            "app4.js": """
                import { spawn } from "child_process";
                spawn.exec(req.query.cmd);
            """,
            "app5.js": """
                const cp = require("child_process");
                const [unsafe, safe] = [req.query.cmd, "date"];
                cp.exec(safe);
            """,
            "app6.js": """
                const cp = require("child_process");
                const [, safe] = [req.query.cmd, "date"];
                cp.exec(safe);
            """,
            "app7.js": """
                const cp = require("child_process");
                const { cmd = "safe" } = {};
                cp.exec(cmd);
            """,
            "app8.js": """
                const cp = require("child_process");
                const { unsafe, safe } = {
                    unsafe: req.query.cmd,
                    safe: "date",
                };
                cp.exec(safe);
            """,
            "app9.js": """
                const cp = require("child_process");
                const { cmd = req.query.cmd } = { cmd: "date" };
                cp.exec(cmd);
            """,
            "app10.js": """
                const cp = require("child_process");
                const safe = "date";
                const { unsafe, safe: cmd } = {
                    unsafe: req.query.cmd,
                    safe,
                };
                cp.exec(cmd);
            """,
            "app11.js": """
                const cp = require("child_process");
                const holder = {};
                holder.cmd = req.query.cmd;
                cp.spawn("echo", [other.holder.cmd]);
            """,
            "app12.js": """
                const cp = require("child_process");
                const {safe: cmd} = {"unsafe": req.query.cmd, "safe": "date"};
                cp.exec(cmd);
            """,
            "app13.js": """
                const cp = require("child_process");
                const {"unsafe": unsafe, "safe": cmd} = {
                    "unsafe": req.query.cmd,
                    "safe": "date",
                };
                cp.exec(cmd);
            """,
            "app14.js": """
                const cp = require("child_process");
                const {1: cmd} = {0: req.query.cmd, 1: "date"};
                cp.exec(cmd);
            """,
        },
    )
    assert records == []


def test_shell_ignores_assignment_text_inside_single_quotes(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "run.sh": """
                echo 'CMD=$1'
                eval "$CMD"
            """,
        },
    )

    assert records == []


def test_shell_tracks_tainted_assignment_after_group_prefix(tmp_path):
    records = scan_files(
        tmp_path,
        {"run.sh": '{ CMD="$1"; eval "$CMD"; }'},
    )

    assert len(records) == 1
    assert records[0].severity == Severity.HIGH


def test_preserves_nested_adjacent_exec_aliases(tmp_path):
    records = scan_files(
        tmp_path,
        {
            "app.js": """
                const { exec: x } = require("child_process");
                const y = x;
                x(y(req.query.cmd));
            """,
        },
    )

    assert len(records) == 2
