import ast
import textwrap

from src.rules.A_code.A1_2_1_command_injection_python_taint import PythonTaintMixin
from src.rules.A_code.A1_2_2_command_injection_python_sinks import PythonSinkMixin
from src.rules.A_code.A1_2_3_command_injection_python_sanitizers import (
    PythonSanitizerMixin,
)


def parse_tree(source: str) -> ast.AST:
    return ast.parse(textwrap.dedent(source).strip())


def test_tracks_attribute_and_subscript_assignments():
    tree = parse_tree(
        """
        data = {}
        data["target"] = input()
        box.cmd = data["target"]
        """
    )
    helper = PythonTaintMixin()

    tainted = helper._collect_tainted_names(tree, {})

    assert "data['target']" in tainted
    assert "box.cmd" in tainted


def test_resolves_shell_true_from_bool_binding():
    tree = ast.parse("flag = True")
    helper = PythonSinkMixin()
    bindings = helper._collect_bool_bindings(tree)
    call = ast.parse("subprocess.run(cmd, shell=flag)").body[0].value

    assert helper._shell_true(call, bindings)


def test_accepts_terminating_fullmatch_allowlist():
    tree = parse_tree(
        """
        if not re.fullmatch("^[A-Za-z0-9_.-]+$", user):
            raise ValueError("invalid")
        """
    )
    helper = PythonSanitizerMixin()

    assert helper._collect_sanitized_names(tree, {}) == {"user"}


def test_rejects_non_terminating_regex_check():
    tree = parse_tree(
        """
        if re.match(".*", user):
            pass
        """
    )
    helper = PythonSanitizerMixin()

    assert helper._collect_sanitized_names(tree, {}) == set()
