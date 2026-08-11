import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
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
    offset_to_line_col,
)
from src.rules.A_code.A1_3_1_command_injection_js_ts_sources import JsTsSourceMixin
from src.rules.A_code.A1_3_2_command_injection_js_ts_sinks import JsTsSinkMixin


class CommentRemovalState:
    def __init__(self) -> None:
        self.in_string: Optional[str] = None
        self.in_block_comment: bool = False
        self.in_regex: bool = False
        self.in_regex_class: bool = False
        self.escaped: bool = False
        self.template_depths: List[int] = []


class JsTsCommandInjectionDetector(JsTsSinkMixin, JsTsSourceMixin):
    rule_id = RULE_ID
    category = CATEGORY
    title = TITLE
    severity = DEFAULT_SEVERITY
    _JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}

    def _split_array_literal_elements(self, text: str) -> List[str]:
        parts = []
        current = []
        paren_level = 0
        brace_level = 0
        bracket_level = 0
        in_string = None
        in_regex = False
        in_regex_class = False
        escaped = False
        idx = 0
        while idx < len(text):
            char = text[idx]
            if escaped:
                escaped = False
                current.append(char)
                idx += 1
                continue
            if in_string:
                if char == "\\":
                    escaped = True
                elif char == in_string:
                    in_string = None
                current.append(char)
                idx += 1
                continue
            if in_regex:
                if char == "\\":
                    escaped = True
                elif in_regex_class:
                    if char == "]":
                        in_regex_class = False
                else:
                    if char == "[":
                        in_regex_class = True
                    elif char == "/":
                        in_regex = False
                current.append(char)
                idx += 1
                continue

            if char in {"'", '"', "`"}:
                in_string = char
                current.append(char)
                idx += 1
                continue

            if char == "/":
                prev_token = ""
                p_idx = len(current) - 1
                while p_idx >= 0 and current[p_idx].isspace():
                    p_idx -= 1
                if p_idx >= 0:
                    if current[p_idx].isalnum() or current[p_idx] in {"_", "$"}:
                        end_p = p_idx
                        while p_idx >= 0 and (
                            current[p_idx].isalnum() or current[p_idx] in {"_", "$"}
                        ):
                            p_idx -= 1
                        prev_token = "".join(current[p_idx + 1 : end_p + 1])
                    elif (
                        current[p_idx] == "."
                        and p_idx - 2 >= 0
                        and "".join(current[p_idx - 2 : p_idx + 1]) == "..."
                    ):
                        prev_token = "..."
                    else:
                        prev_token = current[p_idx]

                if prev_token == ")":
                    depth = 1
                    p_search = p_idx - 1
                    while p_search >= 0 and depth > 0:
                        if current[p_search] == ")":
                            depth += 1
                        elif current[p_search] == "(":
                            depth -= 1
                        p_search -= 1
                    if p_search >= 0 and depth == 0:
                        while p_search >= 0 and current[p_search].isspace():
                            p_search -= 1
                        if p_search >= 0:
                            control_keyword = ""
                            if current[p_search].isalnum() or current[p_search] in {
                                "_",
                                "$",
                            }:
                                end_k = p_search
                                while p_search >= 0 and (
                                    current[p_search].isalnum()
                                    or current[p_search] in {"_", "$"}
                                ):
                                    p_search -= 1
                                control_keyword = "".join(
                                    current[p_search + 1 : end_k + 1]
                                )
                            else:
                                control_keyword = current[p_search]
                            if control_keyword in {"if", "while", "for", "switch"}:
                                prev_token = "control_statement"

                regex_start_chars = {
                    "(",
                    "[",
                    ",",
                    "=",
                    ":",
                    "?",
                    "!",
                    "&",
                    "|",
                    "+",
                    "-",
                    "*",
                    "~",
                    ";",
                    "}",
                    ">",
                    "<",
                    "/",
                    "%",
                    "^",
                }
                regex_start_keywords = {
                    "return",
                    "yield",
                    "typeof",
                    "void",
                    "delete",
                    "throw",
                    "default",
                    "await",
                    "case",
                    "else",
                    "do",
                    "instanceof",
                    "in",
                    "new",
                    "control_statement",
                    "...",
                    "of",
                }
                if (
                    prev_token == ""
                    or prev_token in regex_start_chars
                    or prev_token in regex_start_keywords
                ):
                    in_regex = True
                    current.append(char)
                    idx += 1
                    continue

            if char == "(":
                paren_level += 1
            elif char == ")":
                if paren_level > 0:
                    paren_level -= 1
            elif char == "{":
                brace_level += 1
            elif char == "}":
                if brace_level > 0:
                    brace_level -= 1
            elif char == "[":
                bracket_level += 1
            elif char == "]":
                if bracket_level > 0:
                    bracket_level -= 1
            elif (
                char == ","
                and paren_level == 0
                and brace_level == 0
                and bracket_level == 0
            ):
                parts.append("".join(current).strip())
                current = []
                idx += 1
                continue
            current.append(char)
            idx += 1
        parts.append("".join(current).strip())
        return parts

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
        child_process_sinks: Dict[str, str] = {}
        for import_node in iter_ts_nodes(root):
            if getattr(import_node, "type", "") == "import_statement":
                self._register_child_process_imports(
                    ts_node_text(src_bytes, import_node), child_process_sinks
                )
        for node in iter_ts_nodes(root):
            node_type = getattr(node, "type", "")
            text = ts_node_text(src_bytes, node)
            if node_type in {
                "import_statement",
                "lexical_declaration",
                "variable_declaration",
            }:
                self._register_child_process_imports(text, child_process_sinks)
            if node_type in {
                "variable_declarator",
                "assignment_expression",
                "augmented_assignment_expression",
            }:
                left = ts_child_by_field_name(node, "name") or ts_child_by_field_name(
                    node, "left"
                )
                right = ts_child_by_field_name(node, "value") or ts_child_by_field_name(
                    node, "right"
                )
                if left is not None and right is not None:
                    left_text = ts_node_text(src_bytes, left).strip()
                    left_text_norm = self._normalize_property_path(left_text)
                    right_text = ts_node_text(src_bytes, right)
                    right_clean = right_text.strip()

                    left_type = getattr(left, "type", "")
                    if left_type == "object_pattern":
                        is_cp = self._is_child_process_alias_assignment(
                            right_clean, child_process_sinks
                        )
                        is_require_cp = re.fullmatch(
                            r"require\(['\"](?:node:)?child_process['\"]\)",
                            right_clean,
                        )
                        if is_cp or is_require_cp:
                            for child in getattr(left, "named_children", []):
                                c_type = getattr(child, "type", "")
                                prop_name = None
                                local_name = None
                                if c_type == "pair":
                                    key_node = ts_child_by_field_name(child, "key")
                                    val_node = ts_child_by_field_name(child, "value")
                                    if key_node and val_node:
                                        prop_name = ts_node_text(
                                            src_bytes, key_node
                                        ).strip()
                                        local_name = ts_node_text(
                                            src_bytes, val_node
                                        ).strip()
                                else:
                                    prop_name = ts_node_text(src_bytes, child).strip()
                                    local_name = prop_name

                                if prop_name and local_name:
                                    if is_require_cp:
                                        child_process_sinks[local_name] = prop_name
                                    else:
                                        orig_name = (
                                            self._get_child_process_original_name(
                                                f"{right_clean}.{prop_name}",
                                                child_process_sinks,
                                            )
                                        )
                                        if orig_name:
                                            child_process_sinks[local_name] = orig_name
                    else:
                        if re.fullmatch(
                            r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", left_text_norm
                        ) and self._is_child_process_alias_assignment(
                            right_clean, child_process_sinks
                        ):
                            orig_name = self._get_child_process_original_name(
                                right_clean, child_process_sinks
                            )
                            if orig_name:
                                child_process_sinks[left_text_norm] = orig_name

                    if left_type == "object_pattern":
                        rhs_tainted = self._js_has_external_input(
                            right_text, tainted_names
                        )
                        right_properties = {}
                        if getattr(right, "type", "") == "object":
                            for right_child in getattr(right, "named_children", []):
                                right_child_type = getattr(right_child, "type", "")
                                if right_child_type != "pair":
                                    shorthand_name = ts_node_text(
                                        src_bytes, right_child
                                    ).strip()
                                    if re.fullmatch(
                                        r"[A-Za-z_$][\w$]*", shorthand_name
                                    ):
                                        right_properties[shorthand_name] = (
                                            shorthand_name
                                        )
                                    continue
                                key_node = ts_child_by_field_name(right_child, "key")
                                value_node = ts_child_by_field_name(
                                    right_child, "value"
                                )
                                if key_node is not None and value_node is not None:
                                    property_name = ts_node_text(
                                        src_bytes, key_node
                                    ).strip()
                                    property_name = self._normalize_static_property_key(
                                        property_name
                                    )
                                    right_properties[property_name] = ts_node_text(
                                        src_bytes, value_node
                                    )
                        for child in getattr(left, "named_children", []):
                            c_type = getattr(child, "type", "")
                            prop_name = None
                            local_name = None
                            default_node = None
                            if c_type == "pair":
                                key_node = ts_child_by_field_name(child, "key")
                                val_node = ts_child_by_field_name(child, "value")
                                if key_node:
                                    prop_name = ts_node_text(
                                        src_bytes, key_node
                                    ).strip()
                                    prop_name = self._normalize_static_property_key(
                                        prop_name
                                    )
                                if val_node:
                                    val_type = getattr(val_node, "type", "")
                                    if val_type == "assignment_pattern":
                                        left_node = ts_child_by_field_name(
                                            val_node, "left"
                                        )
                                        if left_node:
                                            local_name = ts_node_text(
                                                src_bytes, left_node
                                            ).strip()
                                        default_node = ts_child_by_field_name(
                                            val_node, "right"
                                        )
                                    else:
                                        local_name = ts_node_text(
                                            src_bytes, val_node
                                        ).strip()
                            elif c_type == "assignment_pattern":
                                left_node = ts_child_by_field_name(child, "left")
                                if left_node:
                                    local_name = ts_node_text(
                                        src_bytes, left_node
                                    ).strip()
                                default_node = ts_child_by_field_name(child, "right")
                            else:
                                local_name = ts_node_text(src_bytes, child).strip()
                                prop_name = local_name

                            if local_name:
                                property_value = right_properties.get(prop_name)
                                if prop_name in right_properties:
                                    has_input = self._js_has_external_input(
                                        property_value, tainted_names
                                    )
                                else:
                                    has_input = rhs_tainted
                                default_may_apply = (
                                    not right_properties
                                    or prop_name not in right_properties
                                    or property_value.strip() == "undefined"
                                )
                                if (
                                    not has_input
                                    and default_node is not None
                                    and default_may_apply
                                ):
                                    default_text = ts_node_text(src_bytes, default_node)
                                    has_input = self._js_has_external_input(
                                        default_text, tainted_names
                                    )
                                if has_input:
                                    tainted_names.add(local_name)
                    elif left_type == "array_pattern":
                        right_type = getattr(right, "type", "")
                        if right_type == "array":
                            right_map = {}
                            r_elements = getattr(right, "children", [])
                            r_idx = 0
                            for r_child in r_elements:
                                r_c_type = getattr(r_child, "type", "")
                                if r_c_type == ",":
                                    r_idx += 1
                                    continue
                                if r_c_type in {"[", "]"}:
                                    continue
                                right_map[r_idx] = ts_node_text(src_bytes, r_child)

                            left_elements = getattr(left, "children", [])
                            element_idx = 0
                            for child in left_elements:
                                c_type = getattr(child, "type", "")
                                if c_type == ",":
                                    element_idx += 1
                                    continue
                                if c_type in {"[", "]"}:
                                    continue

                                local_name = None
                                default_node = None
                                if c_type == "assignment_pattern":
                                    left_node = ts_child_by_field_name(child, "left")
                                    if left_node:
                                        local_name = ts_node_text(
                                            src_bytes, left_node
                                        ).strip()
                                    default_node = ts_child_by_field_name(
                                        child, "right"
                                    )
                                else:
                                    local_name = ts_node_text(src_bytes, child).strip()

                                if local_name and re.fullmatch(
                                    r"[A-Za-z_$][\w$]*", local_name
                                ):
                                    has_input = False
                                    if element_idx in right_map:
                                        r_el_text = right_map[element_idx]
                                        has_input = self._js_has_external_input(
                                            r_el_text, tainted_names
                                        )
                                    elif (
                                        c_type == "assignment_pattern"
                                        and default_node is not None
                                    ):
                                        default_text = ts_node_text(
                                            src_bytes, default_node
                                        )
                                        has_input = self._js_has_external_input(
                                            default_text, tainted_names
                                        )
                                    if has_input:
                                        tainted_names.add(local_name)
                        else:
                            rhs_tainted = self._js_has_external_input(
                                right_text, tainted_names
                            )
                            for child in getattr(left, "named_children", []):
                                c_type = getattr(child, "type", "")
                                local_name = None
                                default_node = None
                                if c_type == "assignment_pattern":
                                    left_node = ts_child_by_field_name(child, "left")
                                    if left_node:
                                        local_name = ts_node_text(
                                            src_bytes, left_node
                                        ).strip()
                                    default_node = ts_child_by_field_name(
                                        child, "right"
                                    )
                                else:
                                    local_name = ts_node_text(src_bytes, child).strip()
                                if local_name and re.fullmatch(
                                    r"[A-Za-z_$][\w$]*", local_name
                                ):
                                    has_input = rhs_tainted
                                    if not has_input and default_node is not None:
                                        default_text = ts_node_text(
                                            src_bytes, default_node
                                        )
                                        has_input = self._js_has_external_input(
                                            default_text, tainted_names
                                        )
                                    if has_input:
                                        tainted_names.add(local_name)
                    else:
                        if re.fullmatch(
                            r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", left_text_norm
                        ) and self._js_has_external_input(right_text, tainted_names):
                            tainted_names.add(left_text_norm)
            if node_type != "call_expression":
                continue
            callee_node = ts_child_by_field_name(node, "function")
            if callee_node is None:
                named_children = getattr(node, "named_children", [])
                callee_node = named_children[0] if named_children else None
            if callee_node is None:
                continue
            callee = ts_node_text(src_bytes, callee_node).strip()
            callee = callee.replace("?.", ".")
            callee = re.sub(
                r"^require\(['\"](?:node:)?child_process['\"]\)(?=\.)",
                "child_process",
                callee,
            )
            callee = re.sub(r"^\(\s*([A-Za-z_$][\w$]*)\s*\)(?=!?\.)", r"\1", callee)
            callee = re.sub(r"(?<=[\w$])!(?=\.)", "", callee)
            call_text = text
            sink_node = None
            if callee_node is not None:
                if getattr(callee_node, "type", "") == "member_expression":
                    sink_node = ts_child_by_field_name(callee_node, "property")
                if sink_node is None:
                    sink_node = callee_node

            if sink_node is not None:
                start_point = getattr(sink_node, "start_point", (0, 0))
            else:
                start_point = getattr(node, "start_point", (0, 0))

            node_start_point = getattr(node, "start_point", (0, 0))
            line = node_start_point[0] + 1
            col = start_point[1]
            has_external = self._js_has_external_input(call_text, tainted_names)
            if not has_external:
                continue
            callee_tail = callee.split(".")[-1]
            is_known_sink = (
                callee in child_process_sinks or callee_tail in child_process_sinks
            )
            if not is_known_sink and callee_tail in self._CHILD_PROCESS_NAMES:
                if "." in callee:
                    obj_name = callee.split(".")[0]
                    if child_process_sinks:
                        is_valid = obj_name == "child_process" or (
                            child_process_sinks.get(obj_name) == "child_process"
                        )
                    else:
                        is_valid = obj_name in {"child_process", "cp"}
                    if is_valid:
                        is_known_sink = True
                else:
                    if not child_process_sinks:
                        is_known_sink = True
            if not is_known_sink:
                continue
            byte_offset = (
                getattr(sink_node, "start_byte", 0)
                if sink_node
                else getattr(node, "start_byte", 0)
            )
            if "." in callee:
                obj_name = callee.split(".")[0]
                is_cp_module = child_process_sinks.get(
                    obj_name
                ) == "child_process" or obj_name in {"child_process", "cp"}
                if is_cp_module:
                    resolved_sink = callee_tail
                else:
                    resolved_sink = child_process_sinks.get(callee_tail) or callee_tail
            else:
                resolved_sink = child_process_sinks.get(callee_tail) or callee_tail
            if resolved_sink in {"exec", "execSync"}:
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=line,
                    message="External input reaches child_process command execution",
                )
                rec._column = col
                rec._char_offset = len(
                    src_bytes[:byte_offset].decode("utf-8", errors="replace")
                )
                records.append(rec)
                continue
            if resolved_sink in {"execFile", "execFileSync", "fork"}:
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    file_path=rel_path,
                    line=line,
                    message="External input reaches child_process file execution",
                )
                rec._column = col
                rec._char_offset = len(
                    src_bytes[:byte_offset].decode("utf-8", errors="replace")
                )
                records.append(rec)
                continue
            if resolved_sink in {"spawn", "spawnSync"}:
                has_shell_true = "shell: true" in call_text or "shell:true" in call_text
                rec = RiskRecord(
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
                rec._column = col
                rec._char_offset = len(
                    src_bytes[:byte_offset].decode("utf-8", errors="replace")
                )
                records.append(rec)
        for r in records:
            r._from_ts = True
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
        child_process_sinks: Dict[str, str] = {}
        third_party_shell_sinks: Set[str] = set()
        shell_true_option_names: Set[str] = set()
        lines = src.splitlines()
        raw_lines = src.splitlines(keepends=True)
        statements: List[Tuple[int, str, str, int]] = []
        buffer = ""
        raw_buffer = ""
        start_line = 1
        curr_raw_offset = 0
        stmt_start_offset = 0
        state = CommentRemovalState()
        for i, line in enumerate(lines, start=1):
            comment_removed, _ = self._remove_line_comments(line, state)
            stripped = comment_removed.strip()
            raw_line = raw_lines[i - 1] if 1 <= i <= len(raw_lines) else ""
            if not stripped:
                curr_raw_offset += len(raw_line)
                if buffer:
                    raw_buffer = f"{raw_buffer}{raw_line}"
                continue
            if not buffer:
                start_line = i
                stmt_start_offset = curr_raw_offset
            buffer = f"{buffer} {stripped}".strip()
            raw_buffer = f"{raw_buffer}{raw_line}"
            curr_raw_offset += len(raw_line)
            if stripped.endswith((";", "}", ")")):
                statements.append((start_line, buffer, raw_buffer, stmt_start_offset))
                buffer = ""
                raw_buffer = ""
        if buffer:
            statements.append((start_line, buffer, raw_buffer, stmt_start_offset))
        for static_import in re.finditer(
            r"import\s+[^;]+?\s+from\s+['\"](?:node:)?child_process['\"]", src
        ):
            self._register_child_process_imports(
                static_import.group(0), child_process_sinks
            )
        for static_import in re.finditer(
            r"import\s+[^;]+?\s+from\s+['\"]shelljs['\"]", src
        ):
            self._register_third_party_shell_imports(
                static_import.group(0), third_party_shell_sinks
            )
        for i, stripped, raw_stmt, stmt_start_offset in statements:
            self._register_child_process_imports(stripped, child_process_sinks)
            self._register_third_party_shell_imports(stripped, third_party_shell_sinks)
            for var_names_str, rhs in self._split_declarations(stripped):
                var_names_str = var_names_str.strip()
                rhs = rhs.strip()
                rhs_clean = rhs.rstrip(";").strip()
                names_to_register = []
                if var_names_str.startswith("{") and var_names_str.endswith("}"):
                    inner = var_names_str[1:-1]
                    for part in self._split_array_literal_elements(inner):
                        part = part.strip()
                        if not part:
                            continue
                        default_val = None
                        if "=" in part:
                            lhs_part, rhs_part = part.split("=", 1)
                            lhs_part = lhs_part.strip()
                            default_val = rhs_part.strip()
                            part = lhs_part
                        if ":" in part:
                            p_parts = part.split(":")
                            prop_name = self._normalize_static_property_key(p_parts[0])
                            local_name = p_parts[1].strip()
                            names_to_register.append(
                                (local_name, prop_name, default_val)
                            )
                        else:
                            names_to_register.append((part, part, default_val))
                elif var_names_str.startswith("[") and var_names_str.endswith("]"):
                    inner = var_names_str[1:-1]
                    for part in self._split_array_literal_elements(inner):
                        part = part.strip()
                        if not part:
                            names_to_register.append((None, None, None))
                            continue
                        default_val = None
                        if "=" in part:
                            lhs_part, rhs_part = part.split("=", 1)
                            lhs_part = lhs_part.strip()
                            default_val = rhs_part.strip()
                            part = lhs_part
                        local_name = part.strip()
                        if re.fullmatch(r"[A-Za-z_$][\w$]*", local_name):
                            names_to_register.append((local_name, None, default_val))
                        else:
                            names_to_register.append((None, None, None))
                else:
                    names_to_register.append((var_names_str, None, None))

                is_array_destruct = var_names_str.startswith(
                    "["
                ) and var_names_str.endswith("]")
                rhs_is_array_literal = rhs_clean.startswith("[") and rhs_clean.endswith(
                    "]"
                )
                rhs_elements = []
                if rhs_is_array_literal:
                    rhs_elements = self._split_array_literal_elements(rhs_clean[1:-1])
                is_object_destruct = var_names_str.startswith(
                    "{"
                ) and var_names_str.endswith("}")
                rhs_is_object_literal = rhs_clean.startswith(
                    "{"
                ) and rhs_clean.endswith("}")
                rhs_properties = {}
                if rhs_is_object_literal:
                    for property_text in self._split_array_literal_elements(
                        rhs_clean[1:-1]
                    ):
                        property_match = re.match(
                            r"\s*((?:[A-Za-z_$][\w$]*|[0-9]+(?:\.[0-9]+)?)|(?:['\"`](?:[A-Za-z_$][\w$]*|[0-9]+(?:\.[0-9]+)?)[\"'`]))\s*:\s*(.+)\s*$",
                            property_text,
                        )
                        if property_match:
                            property_name = self._normalize_static_property_key(
                                property_match.group(1)
                            )
                            rhs_properties[property_name] = property_match.group(2)
                        else:
                            shorthand_name = property_text.strip()
                            if re.fullmatch(r"[A-Za-z_$][\w$]*", shorthand_name):
                                rhs_properties[shorthand_name] = shorthand_name

                for element_idx, (var_name, prop_name, default_val) in enumerate(
                    names_to_register
                ):
                    if var_name is None:
                        continue
                    var_name_norm = self._normalize_property_path(var_name)
                    is_require_cp = re.fullmatch(
                        r"require\(['\"](?:node:)?child_process['\"]\)",
                        rhs_clean,
                    )
                    if prop_name is not None:
                        if is_require_cp:
                            child_process_sinks[var_name_norm] = prop_name
                        else:
                            orig_name = self._get_child_process_original_name(
                                f"{rhs_clean}.{prop_name}", child_process_sinks
                            )
                            if orig_name:
                                child_process_sinks[var_name_norm] = orig_name
                    else:
                        orig_name = self._get_child_process_original_name(
                            rhs_clean, child_process_sinks
                        )
                        if orig_name:
                            child_process_sinks[var_name_norm] = orig_name

                    if self._js_options_enable_shell(rhs_clean):
                        shell_true_option_names.add(var_name_norm)

                    if is_array_destruct and rhs_is_array_literal:
                        has_input = False
                        if element_idx < len(rhs_elements):
                            has_input = self._js_has_external_input(
                                rhs_elements[element_idx], tainted_names
                            )
                    elif (
                        is_object_destruct
                        and rhs_is_object_literal
                        and prop_name in rhs_properties
                    ):
                        has_input = self._js_has_external_input(
                            rhs_properties[prop_name], tainted_names
                        )
                    else:
                        has_input = self._js_has_external_input(rhs, tainted_names)

                    property_value = rhs_properties.get(prop_name)
                    default_may_apply = (
                        not (is_object_destruct and rhs_is_object_literal)
                        or prop_name not in rhs_properties
                        or property_value.strip() == "undefined"
                    )
                    if not has_input and default_val is not None and default_may_apply:
                        has_input = self._js_has_external_input(
                            default_val, tainted_names
                        )

                    if has_input:
                        tainted_names.add(var_name_norm)

            if not self._js_has_external_input(stripped, tainted_names):
                continue

            stripped_map = self._build_index_map(raw_stmt)

            # 1. execFile, execFileSync, fork
            file_names = {"execFile", "execFileSync", "fork"}
            if child_process_sinks:
                file_names.update(
                    {
                        alias
                        for alias, orig in child_process_sinks.items()
                        if orig in {"execFile", "execFileSync", "fork"}
                    }
                )

            for name in sorted(file_names):
                for m in re.finditer(f"(?<![\\w$]){re.escape(name)}\\s*\\(", stripped):
                    obj_name = self._member_owner_name(stripped[: m.start()])
                    if obj_name:
                        if child_process_sinks:
                            is_valid = obj_name == "child_process" or (
                                child_process_sinks.get(obj_name) == "child_process"
                            )
                        else:
                            is_valid = obj_name in {"child_process", "cp"}
                        if not is_valid:
                            continue
                        resolved_type = name
                    else:
                        if child_process_sinks and name not in child_process_sinks:
                            continue
                        resolved_type = child_process_sinks.get(name) or name

                    if resolved_type not in {"execFile", "execFileSync", "fork"}:
                        continue
                    start_paren_idx = stripped.find("(", m.start())
                    if start_paren_idx == -1:
                        start_paren_idx = m.end() - 1
                    call_args_text = self._get_argument_list_text(
                        stripped, start_paren_idx
                    )
                    call_text = stripped[
                        m.start() : start_paren_idx + len(call_args_text)
                    ]
                    if not self._js_has_external_input(call_text, tainted_names):
                        continue
                    dot_idx = name.rfind(".")
                    offset = dot_idx + 1 if dot_idx != -1 else 0
                    match_stripped_idx = m.start() + offset
                    if match_stripped_idx < len(stripped_map):
                        raw_offset_in_stmt = stripped_map[match_stripped_idx]
                    else:
                        raw_offset_in_stmt = len(raw_stmt)
                    char_offset = stmt_start_offset + raw_offset_in_stmt
                    line_num, col_num = offset_to_line_col(src, char_offset)

                    rec = RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line=line_num,
                        message="External input reaches child_process file execution",
                    )
                    rec._column = col_num
                    rec._char_offset = char_offset
                    records.append(rec)

            # 2. サードパーティ
            third_party_matches = self._find_all_known_third_party_shell_sinks(stripped)
            for alias in sorted(third_party_shell_sinks - {"exec"}):
                third_party_matches.extend(
                    (match, alias)
                    for match in re.finditer(
                        f"(?<![\\w$]){re.escape(alias)}\\s*\\(", stripped
                    )
                )
            for m, name in third_party_matches:
                if name == "exec":
                    matched_str = m.group(0)
                    if "." in matched_str:
                        obj_name = matched_str.split(".")[0].strip().rstrip("?")
                        if obj_name in {"child_process", "cp"} or (
                            child_process_sinks and obj_name in child_process_sinks
                        ):
                            continue
                    else:
                        obj_name = self._member_owner_name(stripped[: m.start()])
                        if obj_name:
                            if obj_name in {"child_process", "cp"} or (
                                child_process_sinks and obj_name in child_process_sinks
                            ):
                                continue
                        else:
                            if name not in third_party_shell_sinks:
                                continue
                start_paren_idx = stripped.find("(", m.start())
                if start_paren_idx == -1:
                    start_paren_idx = m.end() - 1
                call_args_text = self._get_argument_list_text(stripped, start_paren_idx)
                call_text = stripped[m.start() : start_paren_idx + len(call_args_text)]
                if not self._js_has_external_input(call_text, tainted_names):
                    continue
                matched_str = m.group(0).rstrip(" (")
                dot_idx = matched_str.rfind(".")
                offset = dot_idx + 1 if dot_idx != -1 else 0
                match_stripped_idx = m.start() + offset
                if match_stripped_idx < len(stripped_map):
                    raw_offset_in_stmt = stripped_map[match_stripped_idx]
                else:
                    raw_offset_in_stmt = len(raw_stmt)
                char_offset = stmt_start_offset + raw_offset_in_stmt
                line_num, col_num = offset_to_line_col(src, char_offset)

                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=line_num,
                    message="External input reaches shell command execution helper",
                )
                rec._column = col_num
                rec._char_offset = char_offset
                records.append(rec)

            # 3. exec, execSync
            exec_names = {"exec", "execSync"}
            if child_process_sinks:
                exec_names.update(
                    {
                        alias
                        for alias, orig in child_process_sinks.items()
                        if orig in {"exec", "execSync"}
                    }
                )

            for name in sorted(exec_names):
                for m in re.finditer(f"(?<![\\w$]){re.escape(name)}\\s*\\(", stripped):
                    obj_name = self._member_owner_name(stripped[: m.start()])
                    if obj_name:
                        if child_process_sinks:
                            is_valid = obj_name == "child_process" or (
                                child_process_sinks.get(obj_name) == "child_process"
                            )
                        else:
                            is_valid = obj_name in {"child_process", "cp"}
                        if not is_valid:
                            continue
                        resolved_type = name
                    else:
                        if child_process_sinks and name not in child_process_sinks:
                            continue
                        resolved_type = child_process_sinks.get(name) or name

                    if resolved_type not in {"exec", "execSync"}:
                        continue
                    start_paren_idx = stripped.find("(", m.start())
                    if start_paren_idx == -1:
                        start_paren_idx = m.end() - 1
                    call_args_text = self._get_argument_list_text(
                        stripped, start_paren_idx
                    )
                    call_text = stripped[
                        m.start() : start_paren_idx + len(call_args_text)
                    ]
                    if not self._js_has_external_input(call_text, tainted_names):
                        continue
                    dot_idx = name.rfind(".")
                    offset = dot_idx + 1 if dot_idx != -1 else 0
                    match_stripped_idx = m.start() + offset
                    if match_stripped_idx < len(stripped_map):
                        raw_offset_in_stmt = stripped_map[match_stripped_idx]
                    else:
                        raw_offset_in_stmt = len(raw_stmt)
                    char_offset = stmt_start_offset + raw_offset_in_stmt
                    line_num, col_num = offset_to_line_col(src, char_offset)

                    rec = RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=line_num,
                        message="External input reaches child_process command execution",
                    )
                    rec._column = col_num
                    rec._char_offset = char_offset
                    records.append(rec)

            # 4. spawn, spawnSync
            spawn_names = {"spawn", "spawnSync"}
            if child_process_sinks:
                spawn_names.update(
                    {
                        alias
                        for alias, orig in child_process_sinks.items()
                        if orig in {"spawn", "spawnSync"}
                    }
                )

            for name in sorted(spawn_names):
                for m in re.finditer(f"(?<![\\w$]){re.escape(name)}\\s*\\(", stripped):
                    obj_name = self._member_owner_name(stripped[: m.start()])
                    if obj_name:
                        if child_process_sinks:
                            is_valid = obj_name == "child_process" or (
                                child_process_sinks.get(obj_name) == "child_process"
                            )
                        else:
                            is_valid = obj_name in {"child_process", "cp"}
                        if not is_valid:
                            continue
                        resolved_type = name
                    else:
                        if child_process_sinks and name not in child_process_sinks:
                            continue
                        resolved_type = child_process_sinks.get(name) or name

                    if resolved_type not in {"spawn", "spawnSync"}:
                        continue
                    start_paren_idx = stripped.find("(", m.start())
                    if start_paren_idx == -1:
                        start_paren_idx = m.end() - 1
                    call_args_text = self._get_argument_list_text(
                        stripped, start_paren_idx
                    )
                    call_text = stripped[
                        m.start() : start_paren_idx + len(call_args_text)
                    ]
                    if not self._js_has_external_input(call_text, tainted_names):
                        continue
                    has_shell_true = self._js_call_enables_shell(
                        call_args_text, shell_true_option_names
                    )
                    dot_idx = name.rfind(".")
                    offset = dot_idx + 1 if dot_idx != -1 else 0
                    match_stripped_idx = m.start() + offset
                    if match_stripped_idx < len(stripped_map):
                        raw_offset_in_stmt = stripped_map[match_stripped_idx]
                    else:
                        raw_offset_in_stmt = len(raw_stmt)
                    char_offset = stmt_start_offset + raw_offset_in_stmt
                    line_num, col_num = offset_to_line_col(src, char_offset)

                    rec = RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH if has_shell_true else Severity.MEDIUM,
                        file_path=rel_path,
                        line=line_num,
                        message="External input reaches child_process spawn with shell=true"
                        if has_shell_true
                        else "External input reaches child_process spawn",
                    )
                    rec._column = col_num
                    rec._char_offset = char_offset
                    records.append(rec)
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
    def _is_known_third_party_shell_sink(text: str) -> bool:
        return bool(
            re.search(r"\b(?:shelljs\.)?exec\s*\(", text)
            or re.search(r"\bexeca\.command(?:Sync)?\s*\(", text)
        )

    @staticmethod
    def _find_all_known_third_party_shell_sinks(
        text: str,
    ) -> List[Tuple[re.Match, str]]:
        sinks = []
        patterns = [
            (r"\bshelljs\.exec\s*\(", "exec"),
            (r"(?<!\.)\bexec\s*\(", "exec"),
            (r"\bexeca\.command(?:Sync)?\s*\(", "execa.command"),
        ]
        for pattern, name in patterns:
            for m in re.finditer(pattern, text):
                sinks.append((m, name))
        return sinks

    @staticmethod
    def _register_third_party_shell_imports(text: str, sinks: Set[str]) -> None:
        require_match = re.search(
            r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['\"]shelljs['\"]\)",
            text,
        )
        import_match = re.search(
            r"import\s*\{([^}]+)\}\s*from\s*['\"]shelljs['\"]", text
        )
        for match in (require_match, import_match):
            if match is None:
                continue
            for imported_name in match.group(1).split(","):
                imported_name = imported_name.strip()
                alias_match = re.fullmatch(
                    r"exec\s*(?::|as)\s*([A-Za-z_$][\w$]*)", imported_name
                )
                if alias_match:
                    sinks.add(alias_match.group(1))
                elif imported_name == "exec":
                    sinks.add("exec")

        namespace_patterns = (
            r"(?<![\w$.])(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*require\(['\"]shelljs['\"]\)",
            r"import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['\"]shelljs['\"]",
        )
        for pattern in namespace_patterns:
            for namespace_match in re.finditer(pattern, text):
                sinks.add(f"{namespace_match.group(1)}.exec")

    @staticmethod
    def _member_owner_name(text_before_member: str) -> Optional[str]:
        match = re.search(
            r"(?:(?:\(\s*)?([A-Za-z_$][\w$]*)(?:\s*\))?|require\(['\"]((?:node:)?child_process)['\"]\))\s*!?\s*\??\.\s*$",
            text_before_member,
        )
        if match is None:
            return None
        if match.group(2):
            return "child_process"
        return match.group(1)

    @staticmethod
    def _get_argument_list_text(text: str, start_paren_idx: int) -> str:
        paren_count = 0
        in_string = None
        in_block_comment = False
        in_line_comment = False
        in_regex = False
        in_regex_class = False
        escaped = False
        template_depths: List[int] = []

        idx = start_paren_idx
        while idx < len(text):
            char = text[idx]

            # 1. 1行コメント中の処理
            if in_line_comment:
                if char == "\n":
                    in_line_comment = False
                idx += 1
                continue

            # 2. ブロックコメント中の処理
            if in_block_comment:
                if char == "*" and idx + 1 < len(text) and text[idx + 1] == "/":
                    in_block_comment = False
                    idx += 2
                else:
                    idx += 1
                continue

            # 3. エスケープ処理（文字列と正規表現リテラルの中のみでエスケープを考慮）
            if escaped:
                escaped = False
                idx += 1
                continue

            if not in_string and not in_block_comment and not in_regex:
                if template_depths:
                    if char == "{":
                        template_depths[-1] += 1
                    elif char == "}":
                        if template_depths[-1] > 0:
                            template_depths[-1] -= 1
                        else:
                            template_depths.pop()
                            in_string = "`"
                            idx += 1
                            continue

            if in_string:
                if char == "\\":
                    escaped = True
                elif (
                    in_string == "`"
                    and char == "$"
                    and idx + 1 < len(text)
                    and text[idx + 1] == "{"
                ):
                    template_depths.append(0)
                    in_string = None
                    idx += 2
                    continue
                elif char == in_string:
                    in_string = None
                idx += 1
                continue

            if in_regex:
                if char == "\\":
                    escaped = True
                elif in_regex_class:
                    if char == "]":
                        in_regex_class = False
                else:
                    if char == "[":
                        in_regex_class = True
                    elif char == "/":
                        in_regex = False
                idx += 1
                continue

            # 4. 文字列、コメント、正規表現リテラルの開始判定
            if char == "/" and idx + 1 < len(text):
                next_char = text[idx + 1]
                if next_char == "*":
                    in_block_comment = True
                    idx += 2
                    continue
                elif next_char == "/":
                    in_line_comment = True
                    idx += 2
                    continue
                else:
                    # 正規表現リテラルの開始判定
                    prev_token = ""
                    p_idx = idx - 1
                    while p_idx >= 0 and text[p_idx].isspace():
                        p_idx -= 1
                    if p_idx >= 0:
                        if text[p_idx].isalnum() or text[p_idx] in {"_", "$"}:
                            end_p = p_idx
                            while p_idx >= 0 and (
                                text[p_idx].isalnum() or text[p_idx] in {"_", "$"}
                            ):
                                p_idx -= 1
                            prev_token = text[p_idx + 1 : end_p + 1]
                        else:
                            prev_token = text[p_idx]
                            if p_idx >= 2 and text[p_idx - 2 : p_idx + 1] == "...":
                                prev_token = "..."

                    if prev_token == ")":
                        depth = 1
                        p_search = p_idx - 1
                        while p_search >= 0 and depth > 0:
                            if text[p_search] == ")":
                                depth += 1
                            elif text[p_search] == "(":
                                depth -= 1
                            p_search -= 1
                        if p_search >= 0 and depth == 0:
                            while p_search >= 0 and text[p_search].isspace():
                                p_search -= 1
                            if p_search >= 0:
                                control_keyword = ""
                                if text[p_search].isalnum() or text[p_search] in {
                                    "_",
                                    "$",
                                }:
                                    end_k = p_search
                                    while p_search >= 0 and (
                                        text[p_search].isalnum()
                                        or text[p_search] in {"_", "$"}
                                    ):
                                        p_search -= 1
                                    control_keyword = text[p_search + 1 : end_k + 1]
                                else:
                                    control_keyword = text[p_search]
                                if control_keyword in {"if", "while", "for", "switch"}:
                                    prev_token = "control_statement"

                    regex_start_chars = {
                        "(",
                        "[",
                        ",",
                        "=",
                        ":",
                        "?",
                        "!",
                        "&",
                        "|",
                        "+",
                        "-",
                        "*",
                        "~",
                        ";",
                        "}",
                        ">",
                        "<",
                        "/",
                        "%",
                        "^",
                        "...",
                    }
                    regex_start_keywords = {
                        "return",
                        "yield",
                        "typeof",
                        "void",
                        "delete",
                        "throw",
                        "default",
                        "await",
                        "case",
                        "else",
                        "do",
                        "instanceof",
                        "in",
                        "new",
                        "control_statement",
                    }
                    if (
                        prev_token == ""
                        or prev_token in regex_start_chars
                        or prev_token in regex_start_keywords
                    ):
                        in_regex = True
                        idx += 1
                        continue

            if char in {"'", '"', "`"}:
                in_string = char
                idx += 1
                continue

            # 5. 括弧のカウント
            if char == "(":
                paren_count += 1
            elif char == ")":
                paren_count -= 1
                if paren_count == 0:
                    return text[start_paren_idx : idx + 1]

            idx += 1

        return text[start_paren_idx:]

    @staticmethod
    def _remove_line_comments(
        line: str, state: CommentRemovalState
    ) -> Tuple[str, List[int]]:
        idx = 0
        result = []
        result_indices = []
        while idx < len(line):
            char = line[idx]
            if state.in_block_comment:
                if char == "*" and idx + 1 < len(line) and line[idx + 1] == "/":
                    state.in_block_comment = False
                    idx += 2
                else:
                    idx += 1
                continue
            if state.escaped:
                state.escaped = False
                result.append(char)
                result_indices.append(idx)
                idx += 1
                continue
            if (
                not state.in_string
                and not state.in_block_comment
                and not state.in_regex
            ):
                if (
                    getattr(state, "template_depths", None) is not None
                    and state.template_depths
                ):
                    if char == "{":
                        state.template_depths[-1] += 1
                    elif char == "}":
                        if state.template_depths[-1] > 0:
                            state.template_depths[-1] -= 1
                        else:
                            state.template_depths.pop()
                            state.in_string = "`"
                            result.append(char)
                            result_indices.append(idx)
                            idx += 1
                            continue

            if state.in_string:
                if char == "\\":
                    state.escaped = True
                elif (
                    state.in_string == "`"
                    and char == "$"
                    and idx + 1 < len(line)
                    and line[idx + 1] == "{"
                ):
                    state.template_depths.append(0)
                    state.in_string = None
                    result.append(char)
                    result_indices.append(idx)
                    result.append("{")
                    result_indices.append(idx + 1)
                    idx += 2
                    continue
                elif char == state.in_string:
                    state.in_string = None
                result.append(char)
                result_indices.append(idx)
                idx += 1
                continue
            if state.in_regex:
                if char == "\\":
                    state.escaped = True
                elif state.in_regex_class:
                    if char == "]":
                        state.in_regex_class = False
                else:
                    if char == "[":
                        state.in_regex_class = True
                    elif char == "/":
                        state.in_regex = False
                result.append(char)
                result_indices.append(idx)
                idx += 1
                continue
            if char == "/" and idx + 1 < len(line):
                next_char = line[idx + 1]
                if next_char == "*":
                    state.in_block_comment = True
                    idx += 2
                    continue
                elif next_char == "/":
                    break
                else:
                    # 正規表現リテラルの開始判定
                    prev_token = ""
                    p_idx = len(result) - 1
                    while p_idx >= 0 and result[p_idx].isspace():
                        p_idx -= 1
                    if p_idx >= 0:
                        if result[p_idx].isalnum() or result[p_idx] in {"_", "$"}:
                            end_p = p_idx
                            while p_idx >= 0 and (
                                result[p_idx].isalnum() or result[p_idx] in {"_", "$"}
                            ):
                                p_idx -= 1
                            prev_token = "".join(result[p_idx + 1 : end_p + 1])
                        else:
                            prev_token = result[p_idx]

                    if prev_token == ")":
                        depth = 1
                        p_search = p_idx - 1
                        while p_search >= 0 and depth > 0:
                            if result[p_search] == ")":
                                depth += 1
                            elif result[p_search] == "(":
                                depth -= 1
                            p_search -= 1
                        if p_search >= 0 and depth == 0:
                            while p_search >= 0 and result[p_search].isspace():
                                p_search -= 1
                            if p_search >= 0:
                                control_keyword = ""
                                if result[p_search].isalnum() or result[p_search] in {
                                    "_",
                                    "$",
                                }:
                                    end_k = p_search
                                    while p_search >= 0 and (
                                        result[p_search].isalnum()
                                        or result[p_search] in {"_", "$"}
                                    ):
                                        p_search -= 1
                                    control_keyword = "".join(
                                        result[p_search + 1 : end_k + 1]
                                    )
                                else:
                                    control_keyword = result[p_search]
                                if control_keyword in {"if", "while", "for", "switch"}:
                                    prev_token = "control_statement"

                    regex_start_chars = {
                        "(",
                        "[",
                        ",",
                        "=",
                        ":",
                        "?",
                        "!",
                        "&",
                        "|",
                        "+",
                        "-",
                        "*",
                        "~",
                        ";",
                        "}",
                        ">",
                        "<",
                        "/",
                        "%",
                        "^",
                    }
                    regex_start_keywords = {
                        "return",
                        "yield",
                        "typeof",
                        "void",
                        "delete",
                        "throw",
                        "default",
                        "await",
                        "case",
                        "else",
                        "do",
                        "instanceof",
                        "in",
                        "new",
                        "control_statement",
                    }
                    if (
                        prev_token == ""
                        or prev_token in regex_start_chars
                        or prev_token in regex_start_keywords
                    ):
                        state.in_regex = True
                        result.append(char)
                        result_indices.append(idx)
                        idx += 1
                        continue
            if char in {"'", '"', "`"}:
                state.in_string = char
                result.append(char)
                result_indices.append(idx)
                idx += 1
                continue
            result.append(char)
            result_indices.append(idx)
            idx += 1
        state.escaped = False
        return "".join(result), result_indices

    @staticmethod
    def _build_index_map(raw_stmt: str) -> List[int]:
        raw_lines = []
        curr = ""
        for char in raw_stmt:
            curr += char
            if char == "\n":
                raw_lines.append(curr)
                curr = ""
        if curr:
            raw_lines.append(curr)

        stripped_map = []
        raw_offset = 0
        has_prev = False

        state = CommentRemovalState()
        for line in raw_lines:
            comment_removed, result_indices = (
                JsTsCommandInjectionDetector._remove_line_comments(line, state)
            )
            stripped_line = comment_removed.strip()
            if not stripped_line:
                raw_offset += len(line)
                continue

            lstripped = comment_removed.lstrip()
            left_spaces_in_removed = len(comment_removed) - len(lstripped)
            rstripped_len = len(lstripped.rstrip())

            if has_prev:
                stripped_map.append(raw_offset - 1 if raw_offset > 0 else 0)

            for j in range(rstripped_len):
                removed_char_idx = left_spaces_in_removed + j
                orig_char_idx = result_indices[removed_char_idx]
                stripped_map.append(raw_offset + orig_char_idx)

            has_prev = True
            raw_offset += len(line)

        return stripped_map

    def _split_declarations(self, text: str) -> List[Tuple[str, str]]:
        decls = []
        idx = 0
        in_string = None
        template_depths = []
        in_regex = False
        in_regex_class = False
        escaped = False

        current_var_name = None
        current_rhs_start = -1

        brace_level = 0
        paren_level = 0
        bracket_level = 0

        while idx < len(text):
            char = text[idx]

            if escaped:
                escaped = False
                idx += 1
                continue

            if in_string:
                if char == "\\":
                    escaped = True
                elif (
                    in_string == "`"
                    and char == "$"
                    and idx + 1 < len(text)
                    and text[idx + 1] == "{"
                ):
                    template_depths.append(0)
                    in_string = None
                    idx += 2
                    continue
                elif char == in_string:
                    in_string = None
                idx += 1
                continue

            if not in_string and not in_regex:
                if template_depths:
                    if char == "{":
                        template_depths[-1] += 1
                    elif char == "}":
                        if template_depths[-1] > 0:
                            template_depths[-1] -= 1
                        else:
                            template_depths.pop()
                            in_string = "`"
                            idx += 1
                            continue

            if in_regex:
                if char == "\\":
                    escaped = True
                elif in_regex_class:
                    if char == "]":
                        in_regex_class = False
                else:
                    if char == "[":
                        in_regex_class = True
                    elif char == "/":
                        in_regex = False
                idx += 1
                continue

            if not in_string and not in_regex and not template_depths:
                if char == "{":
                    brace_level += 1
                elif char == "}":
                    if brace_level > 0:
                        brace_level -= 1
                elif char == "(":
                    paren_level += 1
                elif char == ")":
                    if paren_level > 0:
                        paren_level -= 1
                elif char == "[":
                    bracket_level += 1
                elif char == "]":
                    if bracket_level > 0:
                        bracket_level -= 1

            if char in {"'", '"', "`"}:
                in_string = char
                idx += 1
                continue

            if char == "/":
                prev_token = ""
                p_idx = idx - 1
                while p_idx >= 0 and text[p_idx].isspace():
                    p_idx -= 1
                if p_idx >= 0:
                    if text[p_idx].isalnum() or text[p_idx] in {"_", "$"}:
                        end_p = p_idx
                        while p_idx >= 0 and (
                            text[p_idx].isalnum() or text[p_idx] in {"_", "$"}
                        ):
                            p_idx -= 1
                        prev_token = text[p_idx + 1 : end_p + 1]
                    elif (
                        text[p_idx] == "."
                        and p_idx - 2 >= 0
                        and text[p_idx - 2 : p_idx + 1] == "..."
                    ):
                        prev_token = "..."
                    else:
                        prev_token = text[p_idx]

                if prev_token == ")":
                    depth = 1
                    p_search = p_idx - 1
                    while p_search >= 0 and depth > 0:
                        if text[p_search] == ")":
                            depth += 1
                        elif text[p_search] == "(":
                            depth -= 1
                        p_search -= 1
                    if p_search >= 0 and depth == 0:
                        while p_search >= 0 and text[p_search].isspace():
                            p_search -= 1
                        if p_search >= 0:
                            control_keyword = ""
                            if text[p_search].isalnum() or text[p_search] in {"_", "$"}:
                                end_k = p_search
                                while p_search >= 0 and (
                                    text[p_search].isalnum()
                                    or text[p_search] in {"_", "$"}
                                ):
                                    p_search -= 1
                                control_keyword = text[p_search + 1 : end_k + 1]
                            else:
                                control_keyword = text[p_search]
                            if control_keyword in {"if", "while", "for", "switch"}:
                                prev_token = "control_statement"

                regex_start_chars = {
                    "(",
                    "[",
                    ",",
                    "=",
                    ":",
                    "?",
                    "!",
                    "&",
                    "|",
                    "+",
                    "-",
                    "*",
                    "~",
                    ";",
                    "}",
                    ">",
                    "<",
                    "/",
                    "%",
                    "^",
                }
                regex_start_keywords = {
                    "return",
                    "yield",
                    "typeof",
                    "void",
                    "delete",
                    "throw",
                    "default",
                    "await",
                    "case",
                    "else",
                    "do",
                    "instanceof",
                    "in",
                    "new",
                    "control_statement",
                    "...",
                    "of",
                }
                if (
                    prev_token == ""
                    or prev_token in regex_start_chars
                    or prev_token in regex_start_keywords
                ):
                    in_regex = True
                    idx += 1
                    continue

            word_match = re.match(r"\b(const|let|var)\b", text[idx:])
            assign_match = None
            if not word_match:
                is_assign_candidate = (current_var_name is None) or (
                    brace_level > 0 or paren_level > 0 or bracket_level > 0
                )
                if is_assign_candidate:
                    assign_match = re.match(
                        r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`)\s*\])*)\s*(?:\+|-|\*|/|%|&|\||\^|<<|>>>?|\?\?|\|\||&&)?=(?!=)",
                        text[idx:],
                    )
                    if assign_match:
                        p_idx = idx - 1
                        while p_idx >= 0 and text[p_idx].isspace():
                            p_idx -= 1
                        if p_idx >= 0 and text[p_idx] == ".":
                            assign_match = None

            if word_match or assign_match:
                is_boundary = False
                if word_match:
                    is_boundary = (current_var_name is None) or (
                        brace_level == 0 and paren_level == 0 and bracket_level == 0
                    )
                elif assign_match:
                    is_boundary = (current_var_name is None) and (
                        brace_level == 0 and paren_level == 0 and bracket_level == 0
                    )

                if is_boundary:
                    if current_var_name is not None and current_rhs_start != -1:
                        rhs_val = text[current_rhs_start:idx].strip()
                        decls.append((current_var_name, rhs_val))
                        current_var_name = None
                        current_rhs_start = -1

                    if word_match:
                        idx += len(word_match.group(0))
                        brace_level = 0
                        paren_level = 0
                        bracket_level = 0
                        eq_found = -1
                        v_in_string = None
                        v_brace_depth = 0
                        v_paren_depth = 0
                        v_bracket_depth = 0
                        v_idx = idx
                        while v_idx < len(text):
                            v_char = text[v_idx]
                            if v_in_string:
                                if v_char == "\\":
                                    v_idx += 2
                                    continue
                                if v_char == v_in_string:
                                    v_in_string = None
                            else:
                                if v_char in {"'", '"', "`"}:
                                    v_in_string = v_char
                                elif v_char == "{":
                                    v_brace_depth += 1
                                elif v_char == "}":
                                    if v_brace_depth > 0:
                                        v_brace_depth -= 1
                                elif v_char == "(":
                                    v_paren_depth += 1
                                elif v_char == ")":
                                    if v_paren_depth > 0:
                                        v_paren_depth -= 1
                                elif v_char == "[":
                                    v_bracket_depth += 1
                                elif v_char == "]":
                                    if v_bracket_depth > 0:
                                        v_bracket_depth -= 1
                                elif (
                                    v_char == "="
                                    and v_brace_depth == 0
                                    and v_paren_depth == 0
                                    and v_bracket_depth == 0
                                ):
                                    eq_found = v_idx
                                    break
                                elif (
                                    v_char == ";"
                                    and v_brace_depth == 0
                                    and v_paren_depth == 0
                                    and v_bracket_depth == 0
                                ):
                                    break
                            v_idx += 1

                        if eq_found != -1:
                            current_var_name = text[idx:eq_found].strip()
                            current_rhs_start = eq_found + 1
                            idx = eq_found + 1
                            continue
                    else:  # assign_match
                        current_var_name = assign_match.group(1)
                        idx += len(assign_match.group(0))
                        current_rhs_start = idx
                        brace_level = 0
                        paren_level = 0
                        bracket_level = 0
                        continue
                else:
                    inner_start = idx
                    idx_skip = (
                        len(word_match.group(0))
                        if word_match
                        else len(assign_match.group(0))
                    )
                    eq_found = -1
                    v_in_string = None
                    v_brace_depth = 0
                    v_paren_depth = 0
                    v_bracket_depth = 0
                    v_idx = inner_start + idx_skip
                    while v_idx < len(text):
                        v_char = text[v_idx]
                        if v_in_string:
                            if v_char == "\\":
                                v_idx += 2
                                continue
                            if v_char == v_in_string:
                                v_in_string = None
                        else:
                            if v_char in {"'", '"', "`"}:
                                v_in_string = v_char
                            elif v_char == "{":
                                v_brace_depth += 1
                            elif v_char == "}":
                                if v_brace_depth > 0:
                                    v_brace_depth -= 1
                                else:
                                    break
                            elif v_char == "(":
                                v_paren_depth += 1
                            elif v_char == ")":
                                if v_paren_depth > 0:
                                    v_paren_depth -= 1
                                else:
                                    break
                            elif v_char == "[":
                                v_bracket_depth += 1
                            elif v_char == "]":
                                if v_bracket_depth > 0:
                                    v_bracket_depth -= 1
                                else:
                                    break
                            elif (
                                v_char == "="
                                and v_brace_depth == 0
                                and v_paren_depth == 0
                                and v_bracket_depth == 0
                            ):
                                eq_found = v_idx
                            elif (
                                v_char == ";"
                                and v_brace_depth == 0
                                and v_paren_depth == 0
                                and v_bracket_depth == 0
                            ):
                                break
                        v_idx += 1

                    if word_match:
                        if eq_found != -1:
                            inner_var_name = text[
                                inner_start + idx_skip : eq_found
                            ].strip()
                            inner_rhs_val = text[eq_found + 1 : v_idx].strip()
                            decls.append((inner_var_name, inner_rhs_val))
                    else:  # assign_match
                        inner_var_name = assign_match.group(1)
                        inner_rhs_val = text[inner_start + idx_skip : v_idx].strip()
                        decls.append((inner_var_name, inner_rhs_val))

                    idx += idx_skip
                    continue

            if not in_string and not in_regex and not template_depths:
                if (
                    char == ";"
                    and brace_level == 0
                    and paren_level == 0
                    and bracket_level == 0
                ):
                    if current_var_name is not None and current_rhs_start != -1:
                        rhs_val = text[current_rhs_start:idx].strip()
                        decls.append((current_var_name, rhs_val))
                        current_var_name = None
                        current_rhs_start = -1
                elif (
                    char == ","
                    and brace_level == 0
                    and paren_level == 0
                    and bracket_level == 0
                ):
                    if current_var_name is not None and current_rhs_start != -1:
                        rhs_val = text[current_rhs_start:idx].strip()
                        decls.append((current_var_name, rhs_val))
                        current_var_name = None
                        current_rhs_start = -1

            idx += 1

        if current_var_name is not None and current_rhs_start != -1:
            rhs_val = text[current_rhs_start:].strip()
            decls.append((current_var_name, rhs_val))

        return decls

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for js_file in self._iter_js_ts_files(target):
            records.extend(self._evaluate_js_ts_file(js_file, target))
        return dedupe_records(records)
