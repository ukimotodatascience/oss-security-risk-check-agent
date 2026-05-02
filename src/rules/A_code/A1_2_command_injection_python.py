import ast
from pathlib import Path
from typing import Iterable, List

from src.models import RiskRecord, Severity
from src.rules.A_code.A1_1_command_injection_common import (
    CATEGORY,
    DEFAULT_SEVERITY,
    RULE_ID,
    TITLE,
    dedupe_records,
)
from src.rules.A_code.A1_2_2_command_injection_python_sinks import PythonSinkMixin
from src.rules.A_code.A1_2_3_command_injection_python_sanitizers import (
    PythonSanitizerMixin,
)


class PythonCommandInjectionDetector(PythonSanitizerMixin, PythonSinkMixin):
    rule_id = RULE_ID
    category = CATEGORY
    title = TITLE
    severity = DEFAULT_SEVERITY

    def _iter_python_files(self, target: Path) -> Iterable[Path]:
        """Yield Python files under the target directory."""
        for p in target.rglob("*.py"):
            if p.is_file():
                yield p

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for py_file in self._iter_python_files(target):
            try:
                src = py_file.read_text(encoding="utf-8")
                tree = ast.parse(src)
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            aliases = self._collect_import_aliases(tree)
            taint_returning_functions = self._collect_taint_returning_functions(
                tree, aliases
            )
            wrapper_sinks = self._collect_wrapper_sinks(tree, aliases)
            rel_path = str(py_file.relative_to(target))

            for scope in self._iter_analysis_scopes(tree):
                tainted_names = self._collect_tainted_names(
                    scope, aliases, taint_returning_functions
                )
                tainted_names.difference_update(
                    self._collect_sanitized_names(scope, aliases)
                )
                bool_bindings = self._collect_bool_bindings(scope)

                for node in self._walk_scope_nodes(scope):
                    if not isinstance(node, ast.Call):
                        continue

                    callee = self._resolve_name(self._full_name(node.func), aliases)
                    is_wrapper_sink = bool(callee and callee in wrapper_sinks)
                    if callee not in self._DANGEROUS_CALLS and not is_wrapper_sink:
                        continue

                    first_arg = self._extract_command_arg(node)
                    if first_arg is None:
                        continue

                    has_external = self._is_external_input_expr(
                        first_arg, tainted_names, aliases, taint_returning_functions
                    )
                    is_string_build = self._is_string_building_expr(first_arg)
                    taint_detail = self._describe_taint_sources(
                        first_arg, tainted_names, aliases, taint_returning_functions
                    )

                    if callee in self._SHELL_LIKE_CALLS:
                        if has_external and (
                            is_string_build
                            or isinstance(first_arg, (ast.Name, ast.Subscript, ast.Call))
                        ):
                            records.append(
                                RiskRecord(
                                    rule_id=self.rule_id,
                                    category=self.category,
                                    title=self.title,
                                    severity=Severity.HIGH,
                                    file_path=rel_path,
                                    line=getattr(node, "lineno", None),
                                    message=(
                                        "External input reaches shell command execution"
                                        + taint_detail
                                    ),
                                )
                            )
                        continue

                    if callee in self._PROCESS_EXEC_CALLS:
                        if has_external:
                            records.append(
                                RiskRecord(
                                    rule_id=self.rule_id,
                                    category=self.category,
                                    title=self.title,
                                    severity=Severity.HIGH,
                                    file_path=rel_path,
                                    line=getattr(node, "lineno", None),
                                    message=(
                                        "External input reaches process execution"
                                        + taint_detail
                                    ),
                                )
                            )
                        continue

                    if is_wrapper_sink and callee is not None:
                        if self._wrapper_has_external_arg(
                            node,
                            wrapper_sinks[callee],
                            tainted_names,
                            aliases,
                            taint_returning_functions,
                        ):
                            records.append(
                                RiskRecord(
                                    rule_id=self.rule_id,
                                    category=self.category,
                                    title=self.title,
                                    severity=Severity.HIGH,
                                    file_path=rel_path,
                                    line=getattr(node, "lineno", None),
                                    message=(
                                        "External input reaches a command execution "
                                        "wrapper"
                                        + taint_detail
                                    ),
                                )
                            )
                        continue

                    shell_true = self._shell_true(node, bool_bindings)
                    if has_external and shell_true and is_string_build:
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=getattr(node, "lineno", None),
                                message=(
                                    "External input builds a shell command"
                                    + taint_detail
                                ),
                            )
                        )
                        continue

                    if has_external and isinstance(
                        first_arg, (ast.Name, ast.Attribute, ast.Subscript)
                    ):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.HIGH if shell_true else Severity.MEDIUM,
                                file_path=rel_path,
                                line=getattr(node, "lineno", None),
                                message=(
                                    "External input reaches a subprocess command variable"
                                    + taint_detail
                                ),
                            )
                        )
                        continue

                    if (
                        has_external
                        and not shell_true
                        and isinstance(first_arg, (ast.List, ast.Tuple))
                    ):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.MEDIUM,
                                file_path=rel_path,
                                line=getattr(node, "lineno", None),
                                message=(
                                    "External input is used as a command argument"
                                    + taint_detail
                                ),
                            )
                        )

        return dedupe_records(records)
