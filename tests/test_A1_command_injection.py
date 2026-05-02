import tempfile
import textwrap
import unittest
from pathlib import Path

from src.models import Severity
from src.rules.A_code.A1_command_injection import A1CommandInjectionRule


class A1CommandInjectionRuleTest(unittest.TestCase):
    def _scan_files(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, content in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    textwrap.dedent(content).strip() + "\n", encoding="utf-8"
                )
            return A1CommandInjectionRule().evaluate(root)

    def test_python_detects_interprocedural_command_builder(self):
        records = self._scan_files(
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
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)
        self.assertIn("taint:", records[0].message or "")

    def test_python_tracks_dict_and_attribute_values(self):
        records = self._scan_files(
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
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_python_wrapper_ignores_unrelated_parameters(self):
        records = self._scan_files(
            {
                "app.py": """
                    import os

                    def helper(user_value):
                        os.system("date")

                    value = input()
                    helper(value)
                """
            }
        )

        self.assertEqual(records, [])

    def test_python_does_not_treat_non_terminating_regex_check_as_sanitizer(self):
        records = self._scan_files(
            {
                "app.py": """
                    import os
                    import re

                    user = input()
                    if re.match(".*", user):
                        pass
                    os.system(user)
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_python_treats_terminating_fullmatch_allowlist_as_sanitizer(self):
        records = self._scan_files(
            {
                "app.py": """
                    import os
                    import re

                    user = input()
                    if not re.fullmatch("^[A-Za-z0-9_.-]+$", user):
                        raise ValueError("invalid target")
                    os.system(user)
                """
            }
        )

        self.assertEqual(records, [])

    def test_javascript_detects_child_process_module_alias(self):
        records = self._scan_files(
            {
                "app.js": """
                    const cp = require("child_process");
                    const cmd = req.query.cmd;
                    cp.exec(cmd);
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_javascript_detects_function_reference_alias(self):
        records = self._scan_files(
            {
                "app.js": """
                    const cp = require("node:child_process");
                    const run = cp.exec;
                    const cmd = req.query.cmd;
                    run(cmd);
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_javascript_spawn_shell_true_is_high(self):
        records = self._scan_files(
            {
                "app.js": """
                    const { spawn } = require("child_process");
                    const target = req.body.target;
                    spawn("sh", ["-c", "cat " + target], { shell: true });
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_javascript_spawn_shell_true_via_options_variable_is_high(self):
        records = self._scan_files(
            {
                "app.js": """
                    const { spawn } = require("child_process");
                    const opts = { shell: true };
                    const target = req.body.target;
                    spawn("cat", [target], opts);
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_javascript_detects_execa_command_helper(self):
        records = self._scan_files(
            {
                "app.js": """
                    const target = req.query.target;
                    execa.command("cat " + target);
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_shell_detects_dollar_command_substitution(self):
        records = self._scan_files(
            {
                "run.sh": """
                    #!/bin/sh
                    result=$(grep "$1" users.txt)
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_shell_detects_eval_from_read_variable(self):
        records = self._scan_files(
            {
                "run.sh": """
                    #!/bin/sh
                    read cmd
                    eval "$cmd"
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_shell_detects_source_from_argument(self):
        records = self._scan_files(
            {
                "run.sh": """
                    #!/bin/sh
                    source "$1"
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_shell_detects_tainted_command_name_execution(self):
        records = self._scan_files(
            {
                "run.sh": """
                    #!/bin/sh
                    cmd="$1"
                    $cmd --version
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)

    def test_shell_detects_here_string_to_shell(self):
        records = self._scan_files(
            {
                "run.sh": """
                    #!/bin/sh
                    bash <<< "$1"
                """
            }
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].severity, Severity.HIGH)


if __name__ == "__main__":
    unittest.main()
