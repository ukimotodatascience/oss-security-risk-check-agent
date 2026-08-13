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
            if getattr(node, "type", "") == "import_statement":
                text = ts_node_text(src_bytes, node)
                self._register_child_process_imports(text, child_process_sinks)
                self._register_shelljs_imports(text, shelljs_sinks)
        for node in nodes:
            node_type = getattr(node, "type", "")
            text = ts_node_text(src_bytes, node)
            if node_type in {"variable_declarator", "assignment_expression"}:
                self._register_shelljs_imports(text, shelljs_sinks)
                self._reset_child_process_local_bindings(text, child_process_sinks)
                self._register_child_process_imports(text, child_process_sinks)
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
                        r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)",
                        right_clean,
                    ) and re.fullmatch(r"[A-Za-z_$][\w$]*", left_text):
                        child_process_sinks.update(
                            f"{left_text}.{api}" for api in self._CHILD_PROCESS_NAMES
                        )
                    direct_api_alias = re.fullmatch(
                        r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\."
                        r"(execFileSync|execFile|execSync|exec|spawnSync|spawn|fork)",
                        right_clean,
                    )
                    if direct_api_alias and re.fullmatch(
                        r"[A-Za-z_$][\w$]*", left_text
                    ):
                        child_process_sinks.add(
                            f"{left_text}.{direct_api_alias.group(1)}"
                        )
                    if re.fullmatch(
                        "[A-Za-z_$][\\w$]*", left_text
                    ) and self._is_child_process_alias_assignment(
                        right_clean, child_process_sinks
                    ):
                        api = self._child_process_api_for_callee(
                            right_clean, child_process_sinks
                        )
                        if api is not None:
                            child_process_sinks.add(f"{left_text}.{api}")
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
            callee = re.sub(
                r"\(\s*(require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\))\s*\)",
                r"\1",
                callee,
            )
            normalized_callee = re.sub(r"\s*(?:\?\.)\s*", ".", callee)
            normalized_callee = re.sub(r"\s*\.\s*", ".", normalized_callee)
            direct_shelljs_call = bool(
                re.fullmatch(
                    r"require\s*\(\s*['\"]shelljs['\"]\s*\)\.exec",
                    normalized_callee,
                )
            )
            direct_child_process_call = re.fullmatch(
                r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\.([A-Za-z_$][\w$]*)",
                normalized_callee,
            )
            if direct_child_process_call:
                normalized_callee = direct_child_process_call.group(1)
            call_text = text
            line = getattr(node, "start_point", (0, 0))[0] + 1
            has_external = self._js_has_external_input(call_text, tainted_names)
            if not has_external:
                continue
            if (
                normalized_callee in shelljs_sinks or direct_shelljs_call
            ) and not self._is_shadowed_shelljs_sink(
                node, normalized_callee, src_bytes
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
            sink_api = self._child_process_api_for_callee(
                normalized_callee, child_process_sinks
            )
            if sink_api is not None and self._is_shadowed_child_process_sink(
                node, normalized_callee, src_bytes
            ):
                sink_api = None
            is_known_sink = (
                sink_api is not None or direct_child_process_call is not None
            )
            if not is_known_sink and (not child_process_sinks):
                is_known_sink = (
                    callee == callee_tail and callee_tail in self._CHILD_PROCESS_NAMES
                )
            if not is_known_sink:
                continue
            if sink_api is not None:
                callee_tail = sink_api
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
        statements = [
            part
            for statement_line, statement in statements
            for part in self._split_top_level_statements(statement_line, statement)
        ]
        for _, statement in statements:
            self._register_shelljs_imports(statement, shelljs_sinks)
        for i, stripped in statements:
            code_text = self._mask_js_noncode_for_detection(stripped)
            code_text = re.sub(
                r"\(\s*(require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\))\s*\)",
                r"\1",
                code_text,
            )
            self._reset_child_process_local_bindings(stripped, child_process_sinks)
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
                    api = self._child_process_api_for_callee(
                        rhs_clean, child_process_sinks
                    )
                    if api is not None:
                        child_process_sinks.add(f"{var_name}.{api}")
                if self._js_options_enable_shell(rhs_clean):
                    shell_true_option_names.add(var_name)
                else:
                    shell_true_option_names.discard(var_name)
                if self._js_has_external_input(rhs, tainted_names):
                    tainted_names.add(var_name)
            assignment = re.match(
                r"\s*([A-Za-z_$][\w$]*)\s*(?<![=!<>])=(?!=|>)\s*(.+)$",
                stripped,
            )
            if assignment:
                option_name, option_rhs = assignment.groups()
                if self._js_options_enable_shell(option_rhs):
                    shell_true_option_names.add(option_name)
                else:
                    shell_true_option_names.discard(option_name)
            if re.search("\\b(?:execFile|execFileSync|fork)\\s*\\(", code_text):
                if self._js_has_external_input(code_text, tainted_names):
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
                code_text, shelljs_sinks
            ) and not self._line_has_shadowed_shelljs_call(
                lines,
                self._shelljs_call_line(lines, i, shelljs_sinks),
                code_text,
                shelljs_sinks,
            ):
                shell_call_arguments = self._shelljs_call_arguments(
                    code_text, shelljs_sinks
                )
                if shell_call_arguments is not None and self._js_has_external_input(
                    shell_call_arguments, tainted_names
                ):
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
            exec_names = self._child_process_call_names(
                child_process_sinks, {"exec", "execSync"}
            )
            if not child_process_sinks:
                exec_names = {"exec", "execSync"}
            if re.search(
                r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\??\.exec(?:Sync)?\s*\(",
                code_text,
            ) or any(
                (self._contains_js_sink_call(code_text, name) for name in exec_names)
            ):
                if self._line_has_shadowed_child_process_call(code_text, exec_names):
                    continue
                if self._js_has_external_input(code_text, tainted_names):
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
            spawn_names = self._child_process_call_names(
                child_process_sinks, {"spawn", "spawnSync"}
            )
            if not child_process_sinks:
                spawn_names = {"spawn", "spawnSync"}
            if re.search(
                r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\)\??\.spawn(?:Sync)?\s*\(",
                code_text,
            ) or any(
                (self._contains_js_sink_call(code_text, name) for name in spawn_names)
            ):
                if self._line_has_shadowed_child_process_call(code_text, spawn_names):
                    continue
                if not self._js_has_external_input(code_text, tainted_names):
                    continue
                has_shell_true = self._js_call_enables_shell(
                    code_text, shell_true_option_names
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
    def _child_process_call_names(sinks: Set[str], apis: Set[str]) -> Set[str]:
        members_by_base = {}
        for sink in sinks:
            base, separator, api = sink.rpartition(".")
            if separator and api in JsTsCommandInjectionDetector._CHILD_PROCESS_NAMES:
                members_by_base.setdefault(base, set()).add(api)
        names = set()
        for base, registered_apis in members_by_base.items():
            for api in registered_apis & apis:
                names.add(f"{base}.{api}" if len(registered_apis) > 1 else base)
        return names

    @staticmethod
    def _child_process_api_for_callee(callee: str, sinks: Set[str]) -> Optional[str]:
        if callee in sinks:
            return callee.rsplit(".", 1)[-1]
        matching = {
            sink.rsplit(".", 1)[-1]
            for sink in sinks
            if sink.rpartition(".")[0] == callee
        }
        return next(iter(matching)) if len(matching) == 1 else None

    @staticmethod
    def _line_has_shadowed_child_process_call(
        text: str, child_process_sinks: Set[str]
    ) -> bool:
        called_bindings = {
            name.split(".", 1)[0]
            for name in child_process_sinks
            if JsTsCommandInjectionDetector._contains_js_sink_call(text, name)
        }
        if not called_bindings:
            return False
        if any(
            re.search(
                rf"\bfor\s*\([\s\S]*(?:\{{[\s\S]*\b{re.escape(name)}\b[\s\S]*\}}|"
                rf"\[[\s\S]*\b{re.escape(name)}\b[\s\S]*\])[\s\S]+(?:of|in)\s+",
                text,
            )
            for name in called_bindings
        ):
            return True
        parameter_text = JsTsCommandInjectionDetector._function_parameter_text(text)
        if parameter_text and called_bindings & (
            JsTsCommandInjectionDetector._parameter_bindings(parameter_text)
        ):
            return True
        return any(
            name in JsTsCommandInjectionDetector._local_declaration_bindings(text)
            and not JsTsCommandInjectionDetector._is_child_process_declaration_binding(
                text, name
            )
            for name in called_bindings
        )

    @staticmethod
    def _is_shadowed_child_process_sink(node, callee: str, src_bytes: bytes) -> bool:
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
        scope_text = ts_node_text(src_bytes, scope)
        parameter_text = JsTsCommandInjectionDetector._first_parameter_list(scope_text)
        if parameter_text and binding_name in (
            JsTsCommandInjectionDetector._parameter_bindings(parameter_text)
        ):
            return True
        prefix = src_bytes[scope.start_byte : node.start_byte].decode(
            "utf-8", errors="ignore"
        )
        return binding_name in JsTsCommandInjectionDetector._local_declaration_bindings(
            prefix
        ) and not JsTsCommandInjectionDetector._is_child_process_declaration_binding(
            prefix, binding_name
        )

    @staticmethod
    def _is_child_process_declaration_binding(text: str, name: str) -> bool:
        return bool(
            re.search(
                rf"\b(?:const|let|var)\s+{re.escape(name)}\b[^;=]*=\s*"
                r"(?:require\s*\(\s*['\"](?:node:)?child_process['\"]|"
                r"\(*\s*await\s+import\s*\(\s*['\"](?:node:)?child_process['\"]|"
                r"[A-Za-z_$][\w$]*\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork))",
                text,
            )
            or re.search(
                rf"\b(?:const|let|var)\s*\{{[^}}]*\b{re.escape(name)}\b[^}}]*\}}\s*=",
                text,
            )
        )

    @staticmethod
    def _js_options_enable_shell(text: str) -> bool:
        return bool(re.search(r"\{[^}]*\bshell\s*:\s*true\b[^}]*\}", text))

    @staticmethod
    def _contains_js_sink_call(text: str, name: str) -> bool:
        sink_pattern = re.escape(name).replace(r"\.", r"\s*(?:\.|\?\.)\s*")
        return bool(re.search(rf"(?<![\w$.]){sink_pattern}(?:\?\.)?\s*\(", text))

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
            or re.search(
                r"\brequire\s*\(\s*['\"]shelljs['\"]\s*\)\??\.exec\s*\(",
                text,
            )
            or re.search(r"\bexeca\.command(?:Sync)?\s*\(", text)
            or any(
                JsTsCommandInjectionDetector._contains_unshadowed_shelljs_call(
                    text, name
                )
                for name in shelljs_sinks
            )
        )

    @staticmethod
    def _shelljs_call_arguments(text: str, shelljs_sinks: Set[str]) -> Optional[str]:
        patterns = [
            r"\bshelljs\s*(?:\.|\?\.)\s*exec\s*\(",
            r"\brequire\s*\(\s*['\"]shelljs['\"]\s*\)\s*(?:\.|\?\.)\s*exec\s*\(",
            r"\bexeca\s*(?:\.|\?\.)\s*command(?:Sync)?\s*\(",
        ]
        for name in shelljs_sinks:
            sink_pattern = re.escape(name).replace(r"\.", r"\s*(?:\.|\?\.)\s*")
            patterns.append(rf"(?<![\w$.]){sink_pattern}(?:\?\.)?\s*\(")
        matches = [
            match
            for pattern in patterns
            for match in re.finditer(pattern, text)
            if not re.search(r"\bfunction\s*$", text[: match.start()])
        ]
        if not matches:
            return None
        argument_ranges = []
        seen_offsets = set()
        for call_match in sorted(matches, key=lambda match: match.start()):
            opening_paren = call_match.end() - 1
            if opening_paren in seen_offsets:
                continue
            seen_offsets.add(opening_paren)
            depth = 1
            for index in range(opening_paren + 1, len(text)):
                if text[index] == "(":
                    depth += 1
                elif text[index] == ")":
                    depth -= 1
                    if depth == 0:
                        argument_ranges.append(text[opening_paren + 1 : index])
                        break
            else:
                argument_ranges.append(text[opening_paren + 1 :])
        return "\n".join(argument_ranges)

    @staticmethod
    def _contains_unshadowed_shelljs_call(text: str, name: str) -> bool:
        sink_pattern = re.escape(name).replace(r"\.", r"\s*(?:\.|\?\.)\s*")
        call_match = re.search(rf"(?<![\w$.]){sink_pattern}(?:\?\.)?\s*\(", text)
        if call_match is None:
            return False
        binding_name = name.split(".", 1)[0]
        prefix = text[: call_match.start()]
        prefix = JsTsCommandInjectionDetector._remove_completed_inner_blocks(prefix)
        has_local_declaration = re.search(
            rf"\b(?:const|let|var|function|class)\s+{re.escape(binding_name)}\b",
            prefix,
        )
        return not has_local_declaration or (
            JsTsCommandInjectionDetector._is_shelljs_declaration_binding(
                prefix, binding_name
            )
        )

    @staticmethod
    def _line_has_shadowed_shelljs_call(
        lines: List[str], line_number: int, text: str, shelljs_sinks: Set[str]
    ) -> bool:
        called_bindings = set()
        for name in shelljs_sinks:
            sink_pattern = re.escape(name).replace(r"\.", r"\s*(?:\.|\?\.)\s*")
            if re.search(rf"(?<![\w$.]){sink_pattern}(?:\?\.)?\s*\(", text):
                called_bindings.add(name.split(".", 1)[0])
        if not called_bindings:
            return False
        if any(
            JsTsCommandInjectionDetector._has_iteration_binding(text, name)
            for name in called_bindings
        ):
            return True
        full_source = "\n".join(lines)
        line_offset = sum(len(line) + 1 for line in lines[: line_number - 1])
        source_tail = full_source[line_offset:]
        call_offsets = []
        for name in shelljs_sinks:
            sink_pattern = re.escape(name).replace(r"\.", r"\s*(?:\.|\?\.)\s*")
            if match := re.search(
                rf"(?<![\w$.]){sink_pattern}(?:\?\.)?\s*\(", source_tail
            ):
                call_offsets.append(line_offset + match.start())
        call_offset = min(call_offsets, default=line_offset)
        brace_depth = 0
        for char in JsTsCommandInjectionDetector._mask_js_noncode_for_detection(
            full_source[:call_offset]
        ):
            if char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth = max(0, brace_depth - 1)
        if brace_depth == 0 and any(
            re.search(
                rf"\b(?:const|let)\s+{re.escape(name)}\b",
                full_source[call_offset:],
            )
            for name in called_bindings
        ):
            return True
        statement_parameter_text = (
            JsTsCommandInjectionDetector._function_parameter_text(text)
        )
        masked_call_scope = JsTsCommandInjectionDetector._mask_js_noncode_for_detection(
            text
        )
        call_positions = []
        for name in shelljs_sinks:
            sink_pattern = re.escape(name).replace(r"\.", r"(?:\.|\?\.)")
            for call_match in re.finditer(
                rf"(?<![\w$.]){sink_pattern}\s*\(", masked_call_scope
            ):
                call_prefix = masked_call_scope[: call_match.start()]
                if re.search(r"\bfunction\s*$", call_prefix):
                    continue
                call_positions.append(call_match.start())
        lexical_call_scope = JsTsCommandInjectionDetector._enclosing_block_text(
            masked_call_scope, min(call_positions) if call_positions else 0
        )
        lexical_call_scope = (
            JsTsCommandInjectionDetector._remove_completed_inner_blocks(
                lexical_call_scope
            )
        )
        raw_statement_bindings = (
            JsTsCommandInjectionDetector._local_declaration_bindings(lexical_call_scope)
        )
        if any(
            name in raw_statement_bindings
            and not JsTsCommandInjectionDetector._is_shelljs_declaration_binding(
                lexical_call_scope, name
            )
            for name in called_bindings
        ):
            return True
        visible_call_scope = (
            JsTsCommandInjectionDetector._remove_completed_inner_blocks(
                masked_call_scope
            )
        )
        concise_arrow = re.search(
            r"(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>[^{]", visible_call_scope
        )
        if concise_arrow:
            arrow_parameters = concise_arrow.group(1) or concise_arrow.group(2)
            if called_bindings & JsTsCommandInjectionDetector._parameter_bindings(
                arrow_parameters
            ):
                return True
        statement_bindings = JsTsCommandInjectionDetector._local_declaration_bindings(
            visible_call_scope
        )
        if any(
            name in statement_bindings
            and not JsTsCommandInjectionDetector._is_shelljs_declaration_binding(
                visible_call_scope, name
            )
            for name in called_bindings
        ):
            return True
        if any(
            re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", visible_call_scope)
            for name in called_bindings
        ):
            return True
        source_prefix = "\n".join(lines[:line_number])
        visible_source_prefix = (
            JsTsCommandInjectionDetector._remove_completed_function_blocks(
                source_prefix
            )
        )
        for name in called_bindings:
            if JsTsCommandInjectionDetector._has_non_shelljs_reassignment(
                visible_source_prefix, name
            ):
                return True
            if re.search(
                rf"\bfunction\b[^{{]*\{{[^{{}}]*\b(?:const|let|var)\s+"
                rf"{re.escape(name)}\s*=\s*require\s*\(\s*['\"]shelljs['\"]"
                rf"[^{{}}]*\}}",
                source_prefix,
                re.DOTALL,
            ):
                return True
        scopes: List[Set[str]] = [set()]
        for current_line in lines[:line_number]:
            stripped = current_line.strip()
            visible_text = JsTsCommandInjectionDetector._remove_completed_inner_blocks(
                JsTsCommandInjectionDetector._mask_js_noncode_for_detection(stripped)
            )
            if stripped.startswith("}") and len(scopes) > 1:
                scopes.pop()
            opens_block = bool(
                re.search(
                    r"(?:\bfunction\b|=>|\b(?:if|for|while|switch|try|catch|else|do)\b|"
                    r"\b[A-Za-z_$][\w$]*\s*\([^)]*\)\s*)[^{}]*\{",
                    stripped,
                )
                or re.search(r"\bfunction\b[\s\S]*\{", stripped)
                or stripped.endswith("{")
                or stripped == "{"
            )
            if opens_block:
                scopes.append(set())
                parameter_text = JsTsCommandInjectionDetector._function_parameter_text(
                    stripped
                )
                parameters_match = None
                if parameter_text is None:
                    parameters_match = re.search(
                        r"(?:\(([^)]*)\)|([A-Za-z_$][\w$]*))\s*=>", stripped
                    )
                if parameter_text is None and parameters_match is None:
                    parameters_match = re.search(r"\bcatch\s*\(([^)]*)\)", stripped)
                if parameter_text is None and parameters_match is None:
                    parameters_match = re.search(
                        r"\b[A-Za-z_$][\w$]*\s*\(([^)]*)\)\s*\{", stripped
                    )
                if parameters_match:
                    parameter_text = parameters_match.group(1)
                    if parameters_match.lastindex and parameters_match.lastindex > 1:
                        parameter_text = parameter_text or parameters_match.group(2)
                    parameters = JsTsCommandInjectionDetector._parameter_bindings(
                        parameter_text
                    )
                    scopes[-1].update(called_bindings & parameters)
                elif parameter_text is not None:
                    parameters = JsTsCommandInjectionDetector._parameter_bindings(
                        parameter_text
                    )
                    scopes[-1].update(called_bindings & parameters)
                elif statement_parameter_text is not None:
                    parameters = JsTsCommandInjectionDetector._parameter_bindings(
                        statement_parameter_text
                    )
                    scopes[-1].update(called_bindings & parameters)
            for name in called_bindings:
                local_bindings = (
                    JsTsCommandInjectionDetector._local_declaration_bindings(
                        visible_text
                    )
                )
                if (
                    name in local_bindings
                    and not JsTsCommandInjectionDetector._is_shelljs_declaration_binding(
                        visible_text, name
                    )
                ):
                    scopes[-1].add(name)
            if opens_block:
                local_call_positions = []
                for name in shelljs_sinks:
                    sink_pattern = re.escape(name).replace(r"\.", r"\s*(?:\.|\?\.)\s*")
                    if local_call := re.search(
                        rf"(?<![\w$.]){sink_pattern}(?:\?\.)?\s*\(",
                        visible_text,
                    ):
                        local_call_positions.append(local_call.start())
                text_before_call = visible_text[
                    : min(local_call_positions)
                    if local_call_positions
                    else len(visible_text)
                ]
                brace_depth = 0
                for char in text_before_call:
                    if char == "{":
                        brace_depth += 1
                    elif char == "}":
                        brace_depth = max(0, brace_depth - 1)
                if brace_depth == 0:
                    scopes.pop()
        return any(called_bindings & scope for scope in scopes)

    @staticmethod
    def _is_shadowed_shelljs_sink(node, callee: str, src_bytes: bytes) -> bool:
        binding_name = callee.split(".", 1)[0]
        source_text = src_bytes.decode("utf-8", errors="ignore")
        if JsTsCommandInjectionDetector._has_iteration_binding(
            source_text, binding_name
        ):
            return True
        ancestor = getattr(node, "parent", None)
        while ancestor is not None:
            if getattr(ancestor, "type", "") in {
                "for_in_statement",
                "for_statement",
            }:
                header = ts_node_text(src_bytes, ancestor)
                iteration_match = re.search(
                    r"\bfor\s*\(\s*(?:const|let|var)\s+(.+?)\s+(?:of|in)\s+",
                    header,
                )
                if iteration_match and binding_name in (
                    JsTsCommandInjectionDetector._parameter_bindings(
                        iteration_match.group(1)
                    )
                ):
                    return True
            ancestor = getattr(ancestor, "parent", None)
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
            prefix = src_bytes[: node.start_byte].decode("utf-8", errors="ignore")
            prefix = JsTsCommandInjectionDetector._remove_completed_function_blocks(
                prefix
            )
        else:
            prefix = src_bytes[scope.start_byte : node.start_byte].decode(
                "utf-8", errors="ignore"
            )
        if JsTsCommandInjectionDetector._has_non_shelljs_reassignment(
            prefix, binding_name
        ):
            return True
        if scope is None:
            return False
        lexical_scope = getattr(node, "parent", None)
        while lexical_scope is not None and getattr(lexical_scope, "type", "") not in {
            "statement_block",
            "class_body",
        }:
            lexical_scope = getattr(lexical_scope, "parent", None)
        if lexical_scope is not None:
            lexical_text = ts_node_text(src_bytes, lexical_scope)
            lexical_text = JsTsCommandInjectionDetector._remove_completed_inner_blocks(
                lexical_text
            )
            lexical_bindings = JsTsCommandInjectionDetector._local_declaration_bindings(
                lexical_text
            )
            if (
                binding_name in lexical_bindings
                and not JsTsCommandInjectionDetector._is_shelljs_declaration_binding(
                    lexical_text, binding_name
                )
            ):
                return True
        shelljs_declaration = re.search(
            rf"\b(?:const|let|var)\s+{re.escape(binding_name)}\s*=\s*"
            rf"require\s*\(\s*['\"]shelljs['\"]\s*\)(?:\.exec)?\b",
            prefix,
        )
        if shelljs_declaration:
            return False
        scope_header = src_bytes[scope.start_byte : scope.start_byte + 500].decode(
            "utf-8", errors="ignore"
        )
        parameter_text = JsTsCommandInjectionDetector._first_parameter_list(
            scope_header
        )
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
        parameters = (
            JsTsCommandInjectionDetector._parameter_bindings(parameter_text)
            if parameter_text
            else set()
        )
        if binding_name in parameters:
            return True
        scope_body = ts_child_by_field_name(scope, "body")
        has_hoisted_binding = (
            any(
                getattr(candidate, "type", "") == "function_declaration"
                and getattr(candidate, "parent", None) is scope_body
                and re.search(
                    rf"\bfunction\s+{re.escape(binding_name)}\s*\(",
                    ts_node_text(src_bytes, candidate),
                )
                for candidate in iter_ts_nodes(scope_body)
            )
            if scope_body is not None
            else False
        )
        if has_hoisted_binding:
            return True
        prefix = JsTsCommandInjectionDetector._remove_completed_inner_blocks(prefix)
        return binding_name in JsTsCommandInjectionDetector._local_declaration_bindings(
            prefix
        )

    def _register_embedded_shelljs_declarations(
        self, text: str, shelljs_sinks: Set[str]
    ) -> None:
        searchable_text = self._mask_js_strings_and_comments(text)
        for match in re.finditer(
            r"(?:const|let|var)\s+(?:[A-Za-z_$][\w$]*|\{[^}]+\})\s*=\s*(?:"
            r"require\s*\(\s*['\"]shelljs['\"]\s*\)(?:\.exec)?|"
            r"\(*\s*await\s+import\s*\(\s*['\"]shelljs['\"]\s*\)\s*\)*"
            r"(?:\s*\.\s*default)?)\s*;?",
            text,
        ):
            if searchable_text[match.start()].isspace():
                continue
            if not re.search(
                r"(?:\bfunction\b|=>|\b(?:get|set|async)?\s*[A-Za-z_$][\w$]*\s*\([^)]*\))[^{}]*\{",
                text[: match.start()],
            ):
                continue
            self._register_shelljs_imports(
                text[match.start() : match.end()], shelljs_sinks
            )

    @staticmethod
    def _function_parameter_text(text: str) -> Optional[str]:
        function_match = re.search(r"\bfunction\b", text)
        if function_match is None:
            return None
        return JsTsCommandInjectionDetector._first_parameter_list(
            text[function_match.end() :]
        )

    @staticmethod
    def _first_parameter_list(text: str) -> Optional[str]:
        open_paren = text.find("(")
        if open_paren == -1:
            return None
        depth = 1
        for index in range(open_paren + 1, len(text)):
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
                if depth == 0:
                    return text[open_paren + 1 : index]
        return None

    @staticmethod
    def _has_non_shelljs_reassignment(text: str, binding_name: str) -> bool:
        assignments = list(
            re.finditer(
                rf"(?:^|[;\n])\s*{re.escape(binding_name)}\s*"
                r"(?<![=!<>])=(?!=|>)\s*"
                r"([^;\n]+)",
                JsTsCommandInjectionDetector._mask_js_noncode_for_detection(text),
            )
        )
        if not assignments:
            return False
        latest_rhs = assignments[-1].group(1).strip()
        return not bool(
            re.match(r"require\s*\(\s*['\"]shelljs['\"]\s*\)(?:\.exec)?", latest_rhs)
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
            if char == "/":
                prefix = text[:index].rstrip()
                if JsTsCommandInjectionDetector._starts_regex_literal(prefix):
                    masked[index] = " "
                    index += 1
                    regex_escaped = False
                    in_character_class = False
                    while index < len(text):
                        regex_char = text[index]
                        masked[index] = " "
                        if regex_char == "[" and not regex_escaped:
                            in_character_class = True
                        elif regex_char == "]" and not regex_escaped:
                            in_character_class = False
                        elif (
                            regex_char == "/"
                            and not regex_escaped
                            and not in_character_class
                        ):
                            index += 1
                            break
                        regex_escaped = regex_char == "\\" and not regex_escaped
                        if regex_char != "\\":
                            regex_escaped = False
                        index += 1
                    continue
            if char in {"'", '"', "`"}:
                quote = char
                masked[index] = " "
            index += 1
        return "".join(masked)

    @staticmethod
    def _parameter_binding(parameter: str) -> str:
        return re.split(r"[?:=]", parameter.strip(), maxsplit=1)[0].strip()

    @staticmethod
    def _parameter_bindings(parameter_text: str) -> Set[str]:
        bindings: Set[str] = set()
        for parameter in JsTsCommandInjectionDetector._split_top_level(
            parameter_text, ","
        ):
            parameter = parameter.strip()
            if not parameter:
                continue
            parameter = parameter.removeprefix("...").strip()
            parameter = JsTsCommandInjectionDetector._split_top_level(
                parameter, "=", maxsplit=1
            )[0].strip()
            if parameter.startswith("{") and parameter.endswith("}"):
                for entry in JsTsCommandInjectionDetector._split_top_level(
                    parameter[1:-1], ","
                ):
                    parts = JsTsCommandInjectionDetector._split_top_level(
                        entry, ":", maxsplit=1
                    )
                    binding = parts[-1].strip()
                    bindings.update(
                        JsTsCommandInjectionDetector._parameter_bindings(binding)
                    )
                continue
            if parameter.startswith("[") and parameter.endswith("]"):
                bindings.update(
                    JsTsCommandInjectionDetector._parameter_bindings(parameter[1:-1])
                )
                continue
            parameter = (
                JsTsCommandInjectionDetector._split_top_level(
                    parameter, ":", maxsplit=1
                )[0]
                .rstrip("?")
                .strip()
            )
            parameter = re.sub(
                r"^(?:(?:public|private|protected|readonly|override)\s+)+",
                "",
                parameter,
            )
            if re.fullmatch(r"[A-Za-z_$][\w$]*", parameter):
                bindings.add(parameter)
        return bindings

    @staticmethod
    def _local_declaration_bindings(text: str) -> Set[str]:
        bindings = set(re.findall(r"\b(?:function|class)\s+([A-Za-z_$][\w$]*)", text))
        for match in re.finditer(r"\b(?:const|let|var)\s+([^;]+)", text, re.DOTALL):
            for declarator in JsTsCommandInjectionDetector._split_top_level(
                match.group(1), ","
            ):
                left = JsTsCommandInjectionDetector._split_top_level(
                    declarator, "=", maxsplit=1
                )[0]
                left = re.split(r"\s+(?:of|in)\s+", left, maxsplit=1)[0]
                bindings.update(JsTsCommandInjectionDetector._parameter_bindings(left))
        return bindings

    @staticmethod
    def _is_shelljs_declaration_binding(text: str, name: str) -> bool:
        for match in re.finditer(
            r"\b(?:const|let|var)\s+(.+?)\s*=\s*"
            r"(?:\(*\s*require\s*\(\s*['\"]shelljs['\"]\s*\)\s*\)*"
            r"(?:\.exec)?(?:\s+(?:as|satisfies)\s+[^;]+)?|"
            r"\(*\s*await\s+import\s*\(\s*['\"]shelljs['\"]\s*\)\s*\)*"
            r"(?:\s*\.\s*default)?)",
            text,
            re.DOTALL,
        ):
            if name in JsTsCommandInjectionDetector._parameter_bindings(match.group(1)):
                return True
        return False

    @staticmethod
    def _has_iteration_binding(text: str, binding_name: str) -> bool:
        return bool(
            re.search(
                rf"\bfor\s*\([\s\S]*?\b(?:const|let|var)\s+"
                rf"(?:\{{[\s\S]*?\b{re.escape(binding_name)}\b[\s\S]*?\}}|"
                rf"\[[\s\S]*?\b{re.escape(binding_name)}\b[\s\S]*?\])"
                r"\s+(?:of|in)\b",
                text,
            )
        )

    @staticmethod
    def _split_top_level(text: str, delimiter: str, maxsplit: int = -1) -> List[str]:
        parts: List[str] = []
        start = 0
        depth = 0
        splits = 0
        for index, char in enumerate(text):
            if char in "({[":
                depth += 1
            elif char in ")}]":
                depth = max(0, depth - 1)
            elif (
                char == delimiter and depth == 0 and (maxsplit < 0 or splits < maxsplit)
            ):
                parts.append(text[start:index])
                start = index + 1
                splits += 1
        parts.append(text[start:])
        return parts

    @classmethod
    def _split_top_level_statements(
        cls, start_line: int, text: str
    ) -> List[Tuple[int, str]]:
        masked = cls._mask_js_strings_and_comments(text)
        parts: List[Tuple[int, str]] = []
        start = 0
        depth = 0
        for index, char in enumerate(masked):
            if char in "({[":
                depth += 1
            elif char in ")}]":
                depth = max(0, depth - 1)
                if depth == 0 and re.match(
                    r"\s*(?:async\s+)?function\b", masked[index + 1 :]
                ):
                    part = text[start : index + 1].strip()
                    if part:
                        parts.append((start_line + text[:start].count("\n"), part))
                    start = index + 1
            elif char == ";" and depth == 0:
                part = text[start : index + 1].strip()
                if part:
                    parts.append((start_line + text[:start].count("\n"), part))
                start = index + 1
        remainder = text[start:].strip()
        if remainder:
            parts.append((start_line + text[:start].count("\n"), remainder))
        return parts

    @classmethod
    def _mask_js_noncode_for_detection(cls, text: str) -> str:
        masked = list(cls._mask_js_strings_and_comments(text))
        for element in re.finditer(
            r"<([A-Za-z][\w:.-]*)\b[^>]*>([^<{}]*)</\1\s*>", text
        ):
            content_start, content_end = element.span(2)
            masked[content_start:content_end] = " " * (content_end - content_start)
        for match in re.finditer(
            r"(?:require|import)\s*\(\s*['\"](?:shelljs|(?:node:)?child_process)['\"]\s*\)",
            text,
        ):
            if masked[match.start()] != " ":
                masked[match.start() : match.end()] = text[match.start() : match.end()]
        template_start = None
        escaped = False
        index = 0
        while index < len(text):
            char = text[index]
            if char == "`" and not escaped:
                if template_start is None:
                    template_start = index
                else:
                    template_start = None
            elif template_start is not None and text.startswith("${", index):
                expression_start = index + 2
                expression_end = cls._template_interpolation_end(text, expression_start)
                if expression_end is not None:
                    expression = text[expression_start:expression_end]
                    masked[expression_start:expression_end] = (
                        cls._mask_js_noncode_for_detection(expression)
                    )
                    index = expression_end
            escaped = char == "\\" and not escaped
            if char != "\\":
                escaped = False
            index += 1
        return "".join(masked)

    @staticmethod
    def _template_interpolation_end(text: str, start: int) -> Optional[int]:
        depth = 1
        quote = None
        escaped = False
        in_block_comment = False
        index = start
        while index < len(text):
            char = text[index]
            next_char = text[index + 1] if index + 1 < len(text) else ""
            if in_block_comment:
                if char == "*" and next_char == "/":
                    in_block_comment = False
                    index += 2
                    continue
            elif quote is not None:
                if char == quote and not escaped:
                    quote = None
                escaped = char == "\\" and not escaped
                if char != "\\":
                    escaped = False
            elif char == "/" and next_char == "*":
                in_block_comment = True
                index += 2
                continue
            elif char == "/" and next_char == "/":
                newline = text.find("\n", index)
                index = len(text) if newline == -1 else newline
                continue
            elif char in {"'", '"'}:
                quote = char
            elif char == "/":
                prefix = text[start:index].rstrip()
                if JsTsCommandInjectionDetector._starts_regex_literal(prefix):
                    index += 1
                    regex_escaped = False
                    in_character_class = False
                    while index < len(text):
                        regex_char = text[index]
                        if regex_char == "[" and not regex_escaped:
                            in_character_class = True
                        elif regex_char == "]" and not regex_escaped:
                            in_character_class = False
                        elif (
                            regex_char == "/"
                            and not regex_escaped
                            and not in_character_class
                        ):
                            break
                        regex_escaped = regex_char == "\\" and not regex_escaped
                        if regex_char != "\\":
                            regex_escaped = False
                        index += 1
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return None

    @staticmethod
    def _remove_completed_inner_blocks(text: str) -> str:
        control_pattern = re.compile(
            r"\b(?:if|for|while|switch|try|catch|else|do)\b[^{}]*\{"
        )
        while match := control_pattern.search(text):
            depth = 1
            cursor = match.end()
            while cursor < len(text) and depth:
                if text[cursor] == "{":
                    depth += 1
                elif text[cursor] == "}":
                    depth -= 1
                cursor += 1
            if depth:
                break
            text = text[: match.start()] + text[cursor:]
        independent_block = re.compile(r"(?:(?<=\{)|(?<=;))\s*\{[^{}]*\}")
        while independent_block.search(text):
            text = independent_block.sub("", text)
        return text

    @staticmethod
    def _enclosing_block_text(text: str, position: int) -> str:
        stack = []
        for index, char in enumerate(text[:position]):
            if char == "{":
                stack.append(index)
            elif char == "}" and stack:
                stack.pop()
        if not stack:
            return text
        start = stack[-1]
        depth = 1
        for index in range(start + 1, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    return text[start : index + 1]
        return text[start:]

    @staticmethod
    def _remove_completed_function_blocks(text: str) -> str:
        function_pattern = re.compile(r"\bfunction\b[^{}]*\{")
        while match := function_pattern.search(text):
            depth = 1
            cursor = match.end()
            while cursor < len(text) and depth:
                if text[cursor] == "{":
                    depth += 1
                elif text[cursor] == "}":
                    depth -= 1
                cursor += 1
            if depth:
                break
            text = text[: match.start()] + text[cursor:]
        return text

    @staticmethod
    def _starts_regex_literal(prefix: str) -> bool:
        if not prefix or prefix[-1] in "=(:,[!&|?{};":
            return True
        if prefix.endswith("=>"):
            return True
        return bool(
            re.search(
                r"\b(?:return|throw|case|yield|await|typeof|void|delete|new)\s*$",
                prefix,
            )
        )

    def _shelljs_call_line(
        self, lines: List[str], start_line: int, shelljs_sinks: Set[str]
    ) -> int:
        for line_number in range(start_line, len(lines) + 1):
            line = self._mask_js_noncode_for_detection(lines[line_number - 1])
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
            if char == "/":
                prefix = line[:index].rstrip()
                if JsTsCommandInjectionDetector._starts_regex_literal(prefix):
                    index += 1
                    regex_escaped = False
                    in_character_class = False
                    while index < len(line):
                        regex_char = line[index]
                        if regex_char == "[" and not regex_escaped:
                            in_character_class = True
                        elif regex_char == "]" and not regex_escaped:
                            in_character_class = False
                        elif (
                            regex_char == "/"
                            and not regex_escaped
                            and not in_character_class
                        ):
                            index += 1
                            break
                        regex_escaped = regex_char == "\\" and not regex_escaped
                        if regex_char != "\\":
                            regex_escaped = False
                        index += 1
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
