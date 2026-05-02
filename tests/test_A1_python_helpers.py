import ast
import textwrap
import unittest

from src.rules.A_code.A1_2_1_command_injection_python_taint import PythonTaintMixin
from src.rules.A_code.A1_2_2_command_injection_python_sinks import PythonSinkMixin
from src.rules.A_code.A1_2_3_command_injection_python_sanitizers import (
    PythonSanitizerMixin,
)


class PythonTaintMixinTest(unittest.TestCase):
    def _tree(self, source: str) -> ast.AST:
        return ast.parse(textwrap.dedent(source).strip())

    def test_tracks_attribute_and_subscript_assignments(self):
        tree = self._tree(
            """
            data = {}
            data["target"] = input()
            box.cmd = data["target"]
            """
        )
        helper = PythonTaintMixin()

        tainted = helper._collect_tainted_names(tree, {})

        self.assertIn("data['target']", tainted)
        self.assertIn("box.cmd", tainted)


class PythonSinkMixinTest(unittest.TestCase):
    def test_resolves_shell_true_from_bool_binding(self):
        tree = ast.parse("flag = True")
        helper = PythonSinkMixin()
        bindings = helper._collect_bool_bindings(tree)
        call = ast.parse("subprocess.run(cmd, shell=flag)").body[0].value

        self.assertTrue(helper._shell_true(call, bindings))


class PythonSanitizerMixinTest(unittest.TestCase):
    def _tree(self, source: str) -> ast.AST:
        return ast.parse(textwrap.dedent(source).strip())

    def test_accepts_terminating_fullmatch_allowlist(self):
        tree = self._tree(
            """
            if not re.fullmatch("^[A-Za-z0-9_.-]+$", user):
                raise ValueError("invalid")
            """
        )
        helper = PythonSanitizerMixin()

        self.assertEqual(helper._collect_sanitized_names(tree, {}), {"user"})

    def test_rejects_non_terminating_regex_check(self):
        tree = self._tree(
            """
            if re.match(".*", user):
                pass
            """
        )
        helper = PythonSanitizerMixin()

        self.assertEqual(helper._collect_sanitized_names(tree, {}), set())


if __name__ == "__main__":
    unittest.main()
