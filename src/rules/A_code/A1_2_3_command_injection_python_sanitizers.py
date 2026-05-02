import ast
import re
from typing import Dict, Set

from src.rules.A_code.A1_2_1_command_injection_python_taint import PythonTaintMixin


class PythonSanitizerMixin(PythonTaintMixin):
    def _collect_sanitized_names(
        self, tree: ast.AST, aliases: Dict[str, str]
    ) -> Set[str]:
        """Collect names guarded by a terminating allowlist validation."""
        sanitized: Set[str] = set()
        for node in self._walk_scope_nodes(tree):
            if not isinstance(node, ast.If):
                continue
            enum_sanitized = self._collect_enum_guard_sanitized_name(node)
            if enum_sanitized:
                sanitized.add(enum_sanitized)
                continue
            if (
                not isinstance(node.test, ast.UnaryOp)
                or not isinstance(node.test.op, ast.Not)
                or not isinstance(node.test.operand, ast.Call)
                or not self._if_body_terminates(node)
            ):
                continue

            call = node.test.operand
            callee = self._resolve_name(self._full_name(call.func), aliases)
            if callee != "re.fullmatch" or len(call.args) < 2:
                continue

            pattern, checked = call.args[0], call.args[1]
            if not isinstance(pattern, ast.Constant) or not isinstance(
                pattern.value, str
            ):
                continue
            if not self._is_simple_allowlist_pattern(pattern.value):
                continue

            key = self._expr_key(checked)
            if key:
                sanitized.add(key)
        return sanitized

    def _collect_enum_guard_sanitized_name(self, node: ast.If) -> str | None:
        """Treat terminating literal enum checks as allowlist sanitizers."""
        if not self._if_body_terminates(node):
            return None
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
            and len(test.comparators) == 1
        ):
            return None
        if not self._is_literal_string_collection(test.comparators[0]):
            return None
        return self._expr_key(test.left)

    @staticmethod
    def _is_literal_string_collection(node: ast.AST) -> bool:
        if not isinstance(node, (ast.Set, ast.List, ast.Tuple)) or not node.elts:
            return False
        return all(
            isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            for elt in node.elts
        )

    @staticmethod
    def _is_simple_allowlist_pattern(pattern: str) -> bool:
        return bool(
            pattern
            and pattern.startswith("^")
            and pattern.endswith("$")
            and re.fullmatch(r"[\^\$\[\]A-Za-z0-9_.\\+*?{}|()\-]+", pattern)
            and ".*" not in pattern
        )

    @staticmethod
    def _if_body_terminates(node: ast.If) -> bool:
        return bool(node.body) and all(
            PythonSanitizerMixin._statement_terminates(stmt) for stmt in node.body
        )

    @staticmethod
    def _statement_terminates(node: ast.stmt) -> bool:
        if isinstance(node, (ast.Return, ast.Raise)):
            return True
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            callee = PythonSanitizerMixin._static_full_name(node.value.func)
            return callee in {"exit", "quit", "sys.exit"}
        return False
