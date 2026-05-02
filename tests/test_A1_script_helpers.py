import unittest

from src.rules.A_code.A1_3_1_command_injection_js_ts_sources import JsTsSourceMixin
from src.rules.A_code.A1_3_2_command_injection_js_ts_sinks import JsTsSinkMixin
from src.rules.A_code.A1_4_1_command_injection_shell_sources import ShellSourceMixin


class JsTsHelperTest(unittest.TestCase):
    def test_js_external_input_tokens_and_tainted_names(self):
        helper = JsTsSourceMixin()

        self.assertTrue(helper._js_has_external_input("req.query.cmd", set()))
        self.assertTrue(helper._js_has_external_input("exec(cmd)", {"cmd"}))
        self.assertFalse(helper._js_has_external_input("exec('date')", {"cmd"}))

    def test_registers_child_process_aliases(self):
        helper = JsTsSinkMixin()
        sinks: set[str] = set()

        helper._register_child_process_imports(
            'const cp = require("node:child_process");',
            sinks,
        )

        self.assertIn("cp.exec", sinks)
        self.assertTrue(helper._is_child_process_alias_assignment("cp.exec", sinks))


class ShellHelperTest(unittest.TestCase):
    def test_tracks_read_and_assignment_taint(self):
        helper = ShellSourceMixin()
        tainted: set[str] = set()

        helper._track_shell_taint_from_text("read cmd", tainted)
        helper._track_shell_taint_from_text('wrapped="$cmd"', tainted)

        self.assertIn("cmd", tainted)
        self.assertIn("wrapped", tainted)
        self.assertTrue(helper._shell_expands_external_input("eval $wrapped", tainted))


if __name__ == "__main__":
    unittest.main()
