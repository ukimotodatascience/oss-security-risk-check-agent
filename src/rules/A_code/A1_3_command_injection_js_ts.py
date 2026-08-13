import re
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple
from src.models import RiskRecord, Severity
from src.rules.A_code.A1_1_command_injection_common import (
    CATEGORY,
    DEFAULT_SEVERITY,
    RULE_ID,
    TITLE,
    dedupe_records,
    get_tree_sitter_parser,
    iter_ts_nodes,
    ts_child_by_field_name,
    ts_node_text,
)
from src.rules.A_code.A1_3_1_command_injection_js_ts_sources import JsTsSourceMixin
from src.rules.A_code.A1_3_2_command_injection_js_ts_sinks import JsTsSinkMixin


class JsTsCommandInjectionDetector(JsTsSinkMixin, JsTsSourceMixin):
    rule_id = RULE_ID
    category = CATEGORY
    title = TITLE
    severity = DEFAULT_SEVERITY
    _JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    def _iter_js_ts_files(self, target: Path) -> Iterable[Path]:
        """対象ディレクトリ配下の JavaScript / TypeScript ファイルを列挙する。"""
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._JS_TS_EXTENSIONS:
                yield p

    def _evaluate_js_ts_file_with_tree_sitter(
        self, file_path: Path, target: Path, src: str
    ) -> Optional[List[RiskRecord]]:
        """tree-sitter が利用可能な場合、JS/TS を構文木ベースで評価する。"""
        parser = get_tree_sitter_parser(file_path.suffix.lower())
        if parser is None:
            return None
        src_bytes = src.encode("utf-8")
        parse = getattr(parser, "parse", None)
        if parse is None:
            return None
        try:
            tree = parse(src_bytes)
        except Exception:
            return None
        root = getattr(tree, "root_node", None)
        if root is None:
            return None
        records: List[RiskRecord] = []
        rel_path = str(file_path.relative_to(target))
        tainted_names: Set[str] = set()
        child_process_sinks: Set[str] = set()
        shelljs_sinks: Set[str] = set()
        nodes = list(iter_ts_nodes(root))
        for node in getattr(root, "named_children", []):
            if getattr(node, "type", "") in {
                "import_statement",
                "lexical_declaration",
                "variable_declaration",
            }:
                text = ts_node_text(src_bytes, node)
                self._register_child_process_imports(text, child_process_sinks)
                self._register_shelljs_imports(text, shelljs_sinks)
        for node in nodes:
            node_type = getattr(node, "type", "")
            text = ts_node_text(src_bytes, node)
            if node_type in {
                "import_statement",
                "lexical_declaration",
                "variable_declaration",
            }:
                self._register_child_process_imports(text, child_process_sinks)
                self._register_shelljs_imports(text, shelljs_sinks)
            if node_type in {"variable_declarator", "assignment_expression"}:
                left = ts_child_by_field_name(node, "name") or ts_child_by_field_name(
                    node, "left"
                )
                right = ts_child_by_field_name(node, "value") or ts_child_by_field_name(
                    node, "right"
                )
                if left is not None and right is not None:
                    left_text = ts_node_text(src_bytes, left).strip()
                    right_text = ts_node_text(src_bytes, right)
                    right_clean = right_text.strip()
                    if re.fullmatch(
                        "[A-Za-z_$][\\w$]*", left_text
                    ) and self._is_child_process_alias_assignment(
                        right_clean, child_process_sinks
                    ):
                        child_process_sinks.add(left_text)
                    if re.fullmatch(
                        "[A-Za-z_$][\\w$]*", left_text
                    ) and self._js_has_external_input(right_text, tainted_names):
                        tainted_names.add(left_text)
            if node_type != "call_expression":
                continue
            callee_node = ts_child_by_field_name(node, "function")
            if callee_node is None:
                named_children = getattr(node, "named_children", [])
                callee_node = named_children[0] if named_children else None
            if callee_node is None:
                continue
            callee = ts_node_text(src_bytes, callee_node).strip()
            normalized_callee = callee.replace("?.", ".")
            call_text = text
            line = getattr(node, "start_point", (0, 0))[0] + 1
            has_external = self._js_has_external_input(call_text, tainted_names)
            if not has_external:
                continue
            if (
                normalized_callee in shelljs_sinks
                and not self._is_shadowed_shelljs_sink(
                    node, normalized_callee, src_bytes
                )
            ):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=line,
                        message="External input reaches shell command execution helper",
                    )
                )
                continue
            callee_tail = callee.split(".")[-1]
            is_known_sink = (
                callee in child_process_sinks or callee_tail in child_process_sinks
            )
            if not is_known_sink and (not child_process_sinks):
                is_known_sink = (
                    callee == callee_tail and callee_tail in self._CHILD_PROCESS_NAMES
                )
            if not is_known_sink:
                continue
            if callee_tail in {"exec", "execSync"}:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=line,
                        message="External input reaches child_process command execution",
                    )
                )
                continue
            if callee_tail in {"execFile", "execFileSync", "fork"}:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line=line,
                        message="External input reaches child_process file execution",
                    )
                )
                continue
            if callee_tail in {"spawn", "spawnSync"}:
                has_shell_true = "shell: true" in call_text or "shell:true" in call_text
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH if has_shell_true else Severity.MEDIUM,
                        file_path=rel_path,
                        line=line,
                        message="External input reaches child_process spawn with shell=true"
                        if has_shell_true
                        else "External input reaches child_process spawn",
                    )
                )
        return records

    def _evaluate_js_ts_file(self, file_path: Path, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        rel_path = str(file_path.relative_to(target))
        try:
            src = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return records
        tree_sitter_records = self._evaluate_js_ts_file_with_tree_sitter(
            file_path, target, src
        )
        if tree_sitter_records is not None:
            records.extend(tree_sitter_records)
        tainted_names: Set[str] = set()
        child_process_sinks: Set[str] = set()
        shelljs_sinks: Set[str] = set()
        shell_true_option_names: Set[str] = set()
        lines = src.splitlines()
        statements: List[Tuple[int, str]] = []
        buffer = ""
        start_line = 1
        in_template_literal = False
        in_block_comment = False
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or (
                stripped.startswith("//")
                and not in_template_literal
                and not in_block_comment
            ):
                continue
            complete_import = re.search(
                r"\bfrom\s*['\"][^'\"]+['\"]\s*$|"
                r"\brequire\(['\"][^'\"]+['\"]\)\s*$",
                buffer,
            )
            if (
                buffer
                and not in_template_literal
                and not in_block_comment
                and (
                    stripped.startswith("import ")
                    or (buffer.startswith("import ") and complete_import)
                )
            ):
                statements.append((start_line, buffer))
                buffer = ""
            if not buffer:
                start_line = i
            buffer = f"{buffer}\n{stripped}".strip()
            in_template_literal, in_block_comment = self._scan_js_lexical_state(
                line, in_template_literal, in_block_comment
            )
            if (
                not in_template_literal
                and not in_block_comment
                and stripped.endswith((";", "}", ")"))
            ):
                statements.append((start_line, buffer))
                buffer = ""
        if buffer:
            statements.append((start_line, buffer))
        for _, statement in statements:
            self._register_child_process_imports(statement, child_process_sinks)
            self._register_shelljs_imports(statement, shelljs_sinks)
            self._register_embedded_shelljs_declarations(statement, shelljs_sinks)
        for i, stripped in statements:
            self._register_child_process_imports(stripped, child_process_sinks)
            self._register_shelljs_imports(stripped, shelljs_sinks)
            self._register_embedded_shelljs_declarations(stripped, shelljs_sinks)
            m = re.search(
                "\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(.+)$", stripped
            )
            if m:
                (var_name, rhs) = (m.group(1), m.group(2))
                rhs_clean = rhs.rstrip(";").strip()
                if self._is_child_process_alias_assignment(
                    rhs_clean, child_process_sinks
                ):
                    child_process_sinks.add(var_name)
                if self._js_options_enable_shell(rhs_clean):
                    shell_true_option_names.add(var_name)
                if self._js_has_external_input(rhs, tainted_names):
                    tainted_names.add(var_name)
            if re.search("\\b(?:execFile|execFileSync|fork)\\s*\\(", stripped):
                if self._js_has_external_input(stripped, tainted_names):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=i,
                            message="External input reaches child_process file execution",
                        )
                    )
                continue
            if self._is_known_third_party_shell_sink(
                stripped, shelljs_sinks
            ) and not self._line_has_shadowed_shelljs_call(
                lines, i, stripped, shelljs_sinks
            ):
                if self._js_has_external_input(stripped, tainted_names):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=self._shelljs_call_line(lines, i, shelljs_sinks),
                            message="External input reaches shell command execution helper",
                        )
                    )
                continue
            exec_names = child_process_sinks or {"exec", "execSync"}
            if any(
                (
                    re.search(f"(?<![\\w$.]){re.escape(name)}\\s*\\(", stripped)
                    for name in exec_names
                    if name.split(".")[-1] in {"exec", "execSync"}
                    or name in {"exec", "execSync"}
                    or "." not in name
                )
            ):
                if self._js_has_external_input(stripped, tainted_names):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=i,
                            message="External input reaches child_process command execution",
                        )
                    )
                continue
            spawn_names = child_process_sinks or {"spawn", "spawnSync"}
            if any(
                (
                    re.search(f"(?<![\\w$.]){re.escape(name)}\\s*\\(", stripped)
                    for name in spawn_names
                    if name.split(".")[-1] in {"spawn", "spawnSync"}
                    or name in {"spawn", "spawnSync"}
                    or "." not in name
                )
            ):
                if not self._js_has_external_input(stripped, tainted_names):
                    continue
                has_shell_true = self._js_call_enables_shell(
                    stripped, shell_true_option_names
                )
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH if has_shell_true else Severity.MEDIUM,
                        file_path=rel_path,
                        line=i,
                        message="External input reaches child_process spawn with shell=true"
                        if has_shell_true
                        else "External input reaches child_process spawn",
                    )
                )
        return dedupe_records(records)

    @staticmethod
    def _js_options_enable_shell(text: str) -> bool:
        return bool(re.search(r"\{[^}]*\bshell\s*:\s*true\b[^}]*\}", text))

    def _js_call_enables_shell(
        self, text: str, shell_true_option_names: Set[str]
    ) -> bool:
        if self._js_options_enable_shell(text):
            return True
        return any(
            re.search(rf"[,\s]\s*{re.escape(name)}\s*\)?\s*;?$", text)
            for name in shell_true_option_names
        )

    @staticmethod
    def _is_known_third_party_shell_sink(text: str, shelljs_sinks: Set[str]) -> bool:
        return bool(
            re.search(r"\bshelljs\.exec\s*\(", text)
            or re.search(r"\bexeca\.command(?:Sync)?\s*\(", text)
            or any(
                JsTsCommandInjectionDetector._contains_unshadowed_shelljs_call(
                    text, name
                )
                for name in shelljs_sinks
            )
        )

    @staticmethod
    def _contains_unshadowed_shelljs_call(text: str, name: str) -> bool:
        sink_pattern = re.escape(name).replace(r"\.", r"(?:\.|\?\.)")
        call_match = re.search(rf"(?<![\w$.]){sink_pattern}\s*\(", text)
        if call_match is None:
            return False
        binding_name = name.split(".", 1)[0]
        prefix = text[: call_match.start()]
        return not re.search(
            rf"\b(?:const|let|var|function|class)\s+{re.escape(binding_name)}\b",
            prefix,
        )

    @staticmethod
    def _line_has_shadowed_shelljs_call(
        lines: List[str], line_number: int, text: str, shelljs_sinks: Set[str]
    ) -> bool:
        called_bindings = set()
        for name in shelljs_sinks:
            sink_pattern = re.escape(name).replace(r"\.", r"(?:\.|\?\.)")
            if re.search(rf"(?<![\w$.]){sink_pattern}\s*\(", text):
                called_bindings.add(name.split(".", 1)[0])
        if not called_bindings:
            return False
        scopes: List[Set[str]] = [set()]
        for current_line in lines[:line_number]:
            stripped = current_line.strip()
            if stripped.startswith("}") and len(scopes) > 1:
                scopes.pop()
            opens_block = bool(
                re.search(
                    r"(?:\bfunction\b|=>|\b(?:if|for|while|switch|try|catch|else|do)\b)[^{]*\{",
                    stripped,
                )
                or stripped == "{"
            )
            if opens_block:
                scopes.append(set())
                parameters_match = re.search(r"\bfunction\b[^()]*\(([^)]*)\)", stripped)
                if parameters_match is None:
                    parameters_match = re.search(
                        r"(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>",
                        stripped,
                    )
                if parameters_match is None:
                    parameters_match = re.search(r"\bcatch\s*\(([^)]*)\)", stripped)
                if parameters_match:
                    parameter_text = parameters_match.group(
                        1
                    ) or parameters_match.group(2)
                    parameters = {
                        parameter.strip() for parameter in parameter_text.split(",")
                    }
                    scopes[-1].update(called_bindings & parameters)
            for name in called_bindings:
                if re.search(
                    rf"\b(?:const|let|var|function|class)\s+{re.escape(name)}\b",
                    stripped,
                ) and not re.search(
                    rf"\b(?:const|let|var)\s+{re.escape(name)}\s*=\s*"
                    rf"require\(['\"]shelljs['\"]\)(?:\.exec)?\b",
                    stripped,
                ):
                    scopes[-1].add(name)
        return any(called_bindings & scope for scope in scopes[1:])

    @staticmethod
    def _is_shadowed_shelljs_sink(node, callee: str, src_bytes: bytes) -> bool:
        binding_name = callee.split(".", 1)[0]
        scope = getattr(node, "parent", None)
        while scope is not None and getattr(scope, "type", "") not in {
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
            "catch_clause",
        }:
            scope = getattr(scope, "parent", None)
        if scope is None:
            return False
        prefix = src_bytes[scope.start_byte : node.start_byte].decode(
            "utf-8", errors="ignore"
        )
        shelljs_declaration = re.search(
            rf"\b(?:const|let|var)\s+{re.escape(binding_name)}\s*=\s*"
            rf"require\(['\"]shelljs['\"]\)(?:\.exec)?\b",
            prefix,
        )
        if shelljs_declaration:
            return False
        scope_header = src_bytes[scope.start_byte : scope.start_byte + 500].decode(
            "utf-8", errors="ignore"
        )
        parameters_match = re.search(r"^[^{]*\(([^)]*)\)", scope_header)
        parameter_text = parameters_match.group(1) if parameters_match else None
        if getattr(scope, "type", "") == "catch_clause":
            catch_match = re.search(r"\bcatch\s*\(([^)]*)\)", scope_header)
            if catch_match:
                parameter_text = catch_match.group(1)
        if getattr(scope, "type", "") == "arrow_function":
            arrow_match = re.search(
                r"(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>", scope_header
            )
            if arrow_match:
                parameter_text = arrow_match.group(1) or arrow_match.group(2)
        if parameter_text and re.search(
            rf"(?:^|,)\s*{re.escape(binding_name)}\s*(?:,|$)",
            parameter_text,
        ):
            return True
        return bool(
            re.search(
                rf"\b(?:const|let|var|function|class)\s+{re.escape(binding_name)}\b",
                prefix,
            )
        )

    def _register_embedded_shelljs_declarations(
        self, text: str, shelljs_sinks: Set[str]
    ) -> None:
        searchable_text = self._mask_js_strings_and_comments(text)
        for match in re.finditer(
            r"(?:const|let|var)\s+(?:[A-Za-z_$][\w$]*|\{[^}]+\})\s*=\s*"
            r"require\(['\"]shelljs['\"]\)(?:\.exec)?\s*;?",
            text,
        ):
            if searchable_text[match.start()].isspace():
                continue
            if not re.search(r"\bfunction\b[^{}]*\{", text[: match.start()]):
                continue
            self._register_shelljs_imports(
                text[match.start() : match.end()], shelljs_sinks
            )

    @staticmethod
    def _mask_js_strings_and_comments(text: str) -> str:
        masked = list(text)
        quote = None
        in_block_comment = False
        escaped = False
        index = 0
        while index < len(text):
            char = text[index]
            next_char = text[index + 1] if index + 1 < len(text) else ""
            if in_block_comment:
                masked[index] = " "
                if char == "*" and next_char == "/":
                    masked[index + 1] = " "
                    in_block_comment = False
                    index += 2
                    continue
                index += 1
                continue
            if quote is not None:
                masked[index] = " "
                if char == quote and not escaped:
                    quote = None
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                index += 1
                continue
            if char == "/" and next_char == "/":
                line_end = text.find("\n", index)
                if line_end == -1:
                    line_end = len(text)
                for position in range(index, line_end):
                    masked[position] = " "
                index = line_end
                continue
            if char == "/" and next_char == "*":
                masked[index] = masked[index + 1] = " "
                in_block_comment = True
                index += 2
                continue
            if char in {"'", '"', "`"}:
                quote = char
                masked[index] = " "
            index += 1
        return "".join(masked)

    def _shelljs_call_line(
        self, lines: List[str], start_line: int, shelljs_sinks: Set[str]
    ) -> int:
        for line_number in range(start_line, len(lines) + 1):
            line = lines[line_number - 1]
            if self._is_known_third_party_shell_sink(line, shelljs_sinks):
                return line_number
            if line_number > start_line and line.strip().endswith((";", "}")):
                break
        return start_line

    @staticmethod
    def _scan_js_lexical_state(
        line: str, in_template: bool, in_block_comment: bool
    ) -> Tuple[bool, bool]:
        quote = None
        escaped = False
        index = 0
        while index < len(line):
            char = line[index]
            next_char = line[index + 1] if index + 1 < len(line) else ""
            if in_block_comment:
                if char == "*" and next_char == "/":
                    in_block_comment = False
                    index += 2
                    continue
                index += 1
                continue
            if in_template:
                if char == "`" and not escaped:
                    in_template = False
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                index += 1
                continue
            if quote is not None:
                if char == quote and not escaped:
                    quote = None
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
                index += 1
                continue
            if char == "/" and next_char == "/":
                break
            if char == "/" and next_char == "*":
                in_block_comment = True
                index += 2
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "`":
                in_template = True
            index += 1
        return in_template, in_block_comment

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for js_file in self._iter_js_ts_files(target):
            records.extend(self._evaluate_js_ts_file(js_file, target))
        return dedupe_records(records)
