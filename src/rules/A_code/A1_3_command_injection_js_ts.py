import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union, Any
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

    def _split_and_flatten_array_elements(self, text: str) -> List[str]:
        result = []
        for part in self._split_array_literal_elements(text):
            part = part.strip()
            if part.startswith("..."):
                spread_arg = part[3:].strip()
                if spread_arg.startswith("[") and spread_arg.endswith("]"):
                    sub_inner = spread_arg[1:-1]
                    result.extend(self._split_and_flatten_array_elements(sub_inner))
                else:
                    result.append(part)
            else:
                result.append(part)
        return result

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
        skip_body_node = None
        for node in iter_ts_nodes(root):
            if skip_body_node is not None:
                if (
                    node.start_byte >= skip_body_node.start_byte
                    and node.end_byte <= skip_body_node.end_byte
                ):
                    continue
                else:
                    skip_body_node = None

            node_type = getattr(node, "type", "")
            text = ts_node_text(src_bytes, node)

            # 関数定義のパラメータにおけるデフォルト値の評価 (P2 round 11/12)
            if node_type in {
                "function_declaration",
                "generator_function_declaration",
                "method_definition",
                "arrow_function",
                "function_expression",
            }:
                body_node = ts_child_by_field_name(node, "body")
                if body_node:
                    local_taints = set()
                    params_node = ts_child_by_field_name(node, "parameters")
                    if not params_node:
                        for c in getattr(node, "named_children", []):
                            if getattr(c, "type", "") == "formal_parameters":
                                params_node = c
                                break
                    if params_node:
                        for param in getattr(params_node, "named_children", []):
                            p_type = getattr(param, "type", "")
                            if p_type == "assignment_pattern":
                                p_left = ts_child_by_field_name(param, "left")
                                p_right = ts_child_by_field_name(param, "right")
                                if p_left and p_right:
                                    p_right_text = ts_node_text(src_bytes, p_right)
                                    rhs_tainted = self._js_has_external_input(
                                        p_right_text, tainted_names
                                    )
                                    p_left_type = getattr(p_left, "type", "")
                                    if p_left_type == "identifier":
                                        if rhs_tainted:
                                            p_left_text = ts_node_text(
                                                src_bytes, p_left
                                            ).strip()
                                            local_taints.add(p_left_text)
                                    elif p_left_type in {
                                        "object_pattern",
                                        "array_pattern",
                                    }:
                                        expanded = self._expand_destructuring(
                                            p_left, [], src_bytes
                                        )
                                        for (
                                            local_name,
                                            dest_path,
                                            is_rest,
                                            _,
                                            default_node,
                                        ) in expanded:
                                            if not local_name or not re.fullmatch(
                                                r"[A-Za-z_$][\w$]*", local_name
                                            ):
                                                continue

                                            has_taint = False
                                            if dest_path:
                                                if is_rest:
                                                    has_taint = self._is_rest_tainted(
                                                        p_right,
                                                        dest_path,
                                                        src_bytes,
                                                        tainted_names,
                                                    )
                                                else:
                                                    val_node = (
                                                        self._get_nested_property_value(
                                                            p_right,
                                                            dest_path,
                                                            src_bytes,
                                                        )
                                                    )
                                                    if val_node is not None:
                                                        has_taint = (
                                                            self._js_has_external_input(
                                                                ts_node_text(
                                                                    src_bytes, val_node
                                                                ),
                                                                tainted_names,
                                                            )
                                                        )
                                                    else:
                                                        has_taint = rhs_tainted
                                            else:
                                                has_taint = rhs_tainted

                                            if (
                                                not has_taint
                                                and default_node is not None
                                            ):
                                                def_text = ts_node_text(
                                                    src_bytes, default_node
                                                )
                                                has_taint = self._js_has_external_input(
                                                    def_text, tainted_names
                                                )
                                            if has_taint:
                                                local_taints.add(local_name)
                            elif p_type in {"object_pattern", "array_pattern"}:
                                expanded = self._expand_destructuring(
                                    param, [], src_bytes
                                )
                                for (
                                    local_name,
                                    _,
                                    _,
                                    _,
                                    default_node,
                                ) in expanded:
                                    if not local_name or not re.fullmatch(
                                        r"[A-Za-z_$][\w$]*", local_name
                                    ):
                                        continue
                                    if default_node is not None:
                                        def_text = ts_node_text(src_bytes, default_node)
                                        if self._js_has_external_input(
                                            def_text, tainted_names
                                        ):
                                            local_taints.add(local_name)

                    if local_taints:
                        local_tainted = tainted_names.union(local_taints)
                        local_records = self._evaluate_js_ts_subtree(
                            body_node,
                            target,
                            src_bytes,
                            local_tainted,
                            child_process_sinks,
                            file_path,
                        )
                        if local_records:
                            records.extend(local_records)
                        skip_body_node = body_node
                        continue

            if node_type == "for_in_statement":
                left = ts_child_by_field_name(node, "left")
                right = ts_child_by_field_name(node, "right")
                body_node = ts_child_by_field_name(node, "body")
                if left and right and body_node:
                    right_text = ts_node_text(src_bytes, right)
                    rhs_tainted = self._js_has_external_input(right_text, tainted_names)
                    local_taints = set()

                    left_type = getattr(left, "type", "")
                    if left_type in {"lexical_declaration", "variable_declaration"}:
                        for decl in getattr(left, "named_children", []):
                            if getattr(decl, "type", "") == "variable_declarator":
                                left = ts_child_by_field_name(decl, "name") or decl
                                left_type = getattr(left, "type", "")
                                break

                    if left_type == "identifier":
                        if rhs_tainted:
                            left_text = ts_node_text(src_bytes, left).strip()
                            local_taints.add(left_text)
                    elif left_type in {"object_pattern", "array_pattern"}:
                        expanded = self._expand_destructuring(left, [], src_bytes)
                        for (
                            local_name,
                            dest_path,
                            is_rest,
                            _,
                            default_node,
                        ) in expanded:
                            if not local_name or not re.fullmatch(
                                r"[A-Za-z_$][\w$]*", local_name
                            ):
                                continue

                            has_taint = False
                            if dest_path:
                                if is_rest:
                                    has_taint = self._is_rest_tainted(
                                        right, dest_path, src_bytes, tainted_names
                                    )
                                else:
                                    val_node = self._get_nested_property_value(
                                        right, dest_path, src_bytes
                                    )
                                    if val_node is not None:
                                        has_taint = self._js_has_external_input(
                                            ts_node_text(src_bytes, val_node),
                                            tainted_names,
                                        )
                                    else:
                                        has_taint = rhs_tainted
                            else:
                                has_taint = rhs_tainted

                            if not has_taint and default_node is not None:
                                def_text = ts_node_text(src_bytes, default_node)
                                has_taint = self._js_has_external_input(
                                    def_text, tainted_names
                                )
                            if has_taint:
                                local_taints.add(local_name)

                    if local_taints:
                        local_tainted = tainted_names.union(local_taints)
                        local_records = self._evaluate_js_ts_subtree(
                            body_node,
                            target,
                            src_bytes,
                            local_tainted,
                            child_process_sinks,
                            file_path,
                        )
                        if local_records:
                            records.extend(local_records)
                        skip_body_node = body_node
                        continue

            if node_type in {
                "import_statement",
                "lexical_declaration",
                "variable_declaration",
                "expression_statement",
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
                        ):
                            if self._is_child_process_alias_assignment(
                                right_clean, child_process_sinks
                            ):
                                orig_name = self._get_child_process_original_name(
                                    right_clean, child_process_sinks
                                )
                                if orig_name:
                                    child_process_sinks[left_text_norm] = orig_name
                            elif getattr(right, "type", "") == "object":
                                for child in getattr(right, "named_children", []):
                                    c_type = getattr(child, "type", "")
                                    k_name = None
                                    v_text = None
                                    if c_type == "spread_element":
                                        arg = self._get_spread_argument(child)
                                        if arg:
                                            arg_text = ts_node_text(
                                                src_bytes, arg
                                            ).strip()
                                            orig_name = (
                                                self._get_child_process_original_name(
                                                    arg_text, child_process_sinks
                                                )
                                            )
                                            if orig_name:
                                                child_process_sinks[left_text_norm] = (
                                                    orig_name
                                                )
                                        continue
                                    elif c_type == "pair":
                                        key_node = ts_child_by_field_name(child, "key")
                                        val_node = ts_child_by_field_name(
                                            child, "value"
                                        )
                                        if key_node and val_node:
                                            k_name = ts_node_text(
                                                src_bytes, key_node
                                            ).strip()
                                            k_name = (
                                                self._normalize_static_property_key(
                                                    k_name
                                                )
                                            )
                                            v_text = ts_node_text(
                                                src_bytes, val_node
                                            ).strip()
                                    else:
                                        prop_name = ts_node_text(
                                            src_bytes, child
                                        ).strip()
                                        if prop_name and re.fullmatch(
                                            r"[A-Za-z_$][\w$]*", prop_name
                                        ):
                                            k_name = prop_name
                                            v_text = prop_name

                                    if k_name and v_text:
                                        if self._is_child_process_alias_assignment(
                                            v_text, child_process_sinks
                                        ):
                                            orig_name = (
                                                self._get_child_process_original_name(
                                                    v_text, child_process_sinks
                                                )
                                            )
                                            if orig_name:
                                                child_process_sinks[
                                                    f"{left_text_norm}.{k_name}"
                                                ] = orig_name
                    if left_type in {"object_pattern", "array_pattern"}:
                        rhs_tainted = self._js_has_external_input(
                            right_text, tainted_names
                        )
                        expanded = self._expand_destructuring(left, [], src_bytes)
                        for (
                            local_name,
                            path,
                            is_rest,
                            excluded_keys,
                            default_node,
                        ) in expanded:
                            if not local_name or not re.fullmatch(
                                r"[A-Za-z_$][\w$]*", local_name
                            ):
                                continue
                            if re.fullmatch(
                                r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", right_clean
                            ):
                                path_str = ".".join(
                                    str(p) for p in path if isinstance(p, (str, int))
                                )
                                joined_name = f"{right_clean}.{path_str}"
                                if joined_name in child_process_sinks:
                                    child_process_sinks[local_name] = (
                                        child_process_sinks[joined_name]
                                    )
                            target_node = self._get_nested_property_value(
                                right, path, src_bytes
                            )
                            if is_rest and excluded_keys:
                                has_input = self._is_rest_tainted(
                                    target_node, excluded_keys, tainted_names, src_bytes
                                )
                            elif isinstance(target_node, list):
                                has_input = any(
                                    self._js_has_external_input(
                                        ts_node_text(src_bytes, item), tainted_names
                                    )
                                    for item in target_node
                                )
                            elif target_node is not None:
                                has_input = self._js_has_external_input(
                                    ts_node_text(src_bytes, target_node), tainted_names
                                )
                            else:
                                if getattr(right, "type", "") in {"object", "array"}:
                                    has_input = False
                                else:
                                    has_input = rhs_tainted

                            if not has_input and default_node is not None:
                                default_may_apply = (
                                    target_node is None
                                    or self._js_is_static_undefined(
                                        ts_node_text(src_bytes, target_node)
                                    )
                                )
                                if default_may_apply:
                                    default_text = ts_node_text(src_bytes, default_node)
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
            resolved_sink = self._is_child_process_sink_call(
                callee, child_process_sinks
            )
            if resolved_sink is None:
                continue
            byte_offset = (
                getattr(sink_node, "start_byte", 0)
                if sink_node
                else getattr(node, "start_byte", 0)
            )
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
        active_local_taints = []
        current_brace_level = 0
        for i, stripped, raw_stmt, stmt_start_offset in statements:
            self._register_child_process_imports(stripped, child_process_sinks)
            self._register_third_party_shell_imports(stripped, third_party_shell_sinks)

            # 波括弧レベルの更新
            current_brace_level += stripped.count("{") - stripped.count("}")
            if current_brace_level < 0:
                current_brace_level = 0

            # ステートメント処理開始時点で、現在の波括弧レベルが宣言時より下がった項目をクリアする
            active_local_taints = [
                (param, lvl)
                for param, lvl in active_local_taints
                if current_brace_level >= lvl
            ]

            # for...of / for...in ループの汚染伝播 (P2 round 13)
            for for_match in re.finditer(
                r"\bfor\s*\(\s*(?:(const|let|var)\s+)?(.*?)\s+(of|in)\s+(.*?)\)",
                stripped,
            ):
                _, loop_var, _, loop_src = for_match.groups()
                if loop_var and loop_src:
                    loop_var = loop_var.strip()
                    loop_src = loop_src.strip()

                    current_tainted = tainted_names.union(
                        p for p, _ in active_local_taints
                    )
                    rhs_tainted = self._js_has_external_input(loop_src, current_tainted)

                    is_destruct = (
                        loop_var.startswith("{") and loop_var.endswith("}")
                    ) or (loop_var.startswith("[") and loop_var.endswith("]"))

                    lvl_offset = 1 if stripped.count("{") <= stripped.count("}") else 0

                    if is_destruct:
                        expanded = self._expand_fallback_destructuring(loop_var, [])
                        for local_name, dest_path, _, _, default_val in expanded:
                            if not local_name or not re.fullmatch(
                                r"[A-Za-z_$][\w$]*", local_name
                            ):
                                continue

                            has_taint = False
                            if dest_path:
                                val_text = (
                                    self._get_fallback_nested_property_value_text(
                                        loop_src, dest_path
                                    )
                                )
                                if val_text is not None:
                                    has_taint = self._js_has_external_input(
                                        val_text, current_tainted
                                    )
                                else:
                                    has_taint = rhs_tainted
                            else:
                                has_taint = rhs_tainted

                            if not has_taint and default_val is not None:
                                has_taint = self._js_has_external_input(
                                    default_val, current_tainted
                                )
                            if has_taint:
                                norm_name = self._normalize_property_path(local_name)
                                active_local_taints.append(
                                    (
                                        norm_name,
                                        current_brace_level + lvl_offset,
                                    )
                                )
                    else:
                        if rhs_tainted and re.fullmatch(r"[A-Za-z_$][\w$]*", loop_var):
                            norm_name = self._normalize_property_path(loop_var)
                            active_local_taints.append(
                                (norm_name, current_brace_level + lvl_offset)
                            )

            # 関数引数のデフォルト値汚染伝播 (P2 round 11/12)
            for m in re.finditer(r"\(([^)]+)\)", stripped):
                params_str = m.group(1)
                for part in self._split_array_literal_elements(params_str):
                    part = part.strip()
                    outer_assign = self._split_outer_assignment(part)
                    if outer_assign is not None:
                        p_left_raw, p_right_raw = outer_assign
                        p_left_raw = self._strip_type_annotation(p_left_raw)
                        current_tainted = tainted_names.union(
                            p for p, _ in active_local_taints
                        )
                        rhs_tainted = self._js_has_external_input(
                            p_right_raw, current_tainted
                        )
                        is_dest_param = (
                            p_left_raw.startswith("{") and p_left_raw.endswith("}")
                        ) or (p_left_raw.startswith("[") and p_left_raw.endswith("]"))
                        lvl_offset = (
                            1 if stripped.count("{") <= stripped.count("}") else 0
                        )
                        if is_dest_param:
                            expanded = self._expand_fallback_destructuring(
                                p_left_raw, []
                            )
                            for local_name, dest_path, _, _, default_val in expanded:
                                if not local_name or not re.fullmatch(
                                    r"[A-Za-z_$][\w$]*", local_name
                                ):
                                    continue

                                has_taint = False
                                if dest_path:
                                    val_text = (
                                        self._get_fallback_nested_property_value_text(
                                            p_right_raw, dest_path
                                        )
                                    )
                                    if val_text is not None:
                                        has_taint = self._js_has_external_input(
                                            val_text, current_tainted
                                        )
                                    else:
                                        has_taint = rhs_tainted
                                else:
                                    has_taint = rhs_tainted

                                if not has_taint and default_val is not None:
                                    has_taint = self._js_has_external_input(
                                        default_val, current_tainted
                                    )
                                if has_taint:
                                    norm_name = self._normalize_property_path(
                                        local_name
                                    )
                                    active_local_taints.append(
                                        (
                                            norm_name,
                                            current_brace_level + lvl_offset,
                                        )
                                    )
                        else:
                            if rhs_tainted and re.fullmatch(
                                r"[A-Za-z_$][\w$]*", p_left_raw
                            ):
                                norm_name = self._normalize_property_path(p_left_raw)
                                active_local_taints.append(
                                    (norm_name, current_brace_level + lvl_offset)
                                )
                    else:
                        is_dest_param = (
                            part.startswith("{") and part.endswith("}")
                        ) or (part.startswith("[") and part.endswith("]"))
                        if is_dest_param:
                            current_tainted = tainted_names.union(
                                p for p, _ in active_local_taints
                            )
                            expanded = self._expand_fallback_destructuring(part, [])
                            lvl_offset = (
                                1 if stripped.count("{") <= stripped.count("}") else 0
                            )
                            for local_name, _, _, _, default_val in expanded:
                                if not local_name or not re.fullmatch(
                                    r"[A-Za-z_$][\w$]*", local_name
                                ):
                                    continue
                                if default_val is not None:
                                    if self._js_has_external_input(
                                        default_val, current_tainted
                                    ):
                                        norm_name = self._normalize_property_path(
                                            local_name
                                        )
                                        active_local_taints.append(
                                            (
                                                norm_name,
                                                current_brace_level + lvl_offset,
                                            )
                                        )

            for var_names_str, rhs in self._split_declarations(stripped):
                var_names_str = var_names_str.strip()
                pair = self._split_fallback_pair(var_names_str)
                if pair:
                    var_names_str = pair[0].strip()
                rhs = rhs.strip()
                rhs_clean = rhs.rstrip(";").strip()
                is_destruct = (
                    var_names_str.startswith("{") and var_names_str.endswith("}")
                ) or (var_names_str.startswith("[") and var_names_str.endswith("]"))
                if is_destruct:
                    expanded = self._expand_fallback_destructuring(var_names_str, [])
                    for (
                        local_name,
                        path,
                        is_rest,
                        excluded_keys,
                        default_val,
                    ) in expanded:
                        if not local_name or not re.fullmatch(
                            r"[A-Za-z_$][\w$]*", local_name
                        ):
                            continue
                        if re.fullmatch(
                            r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", rhs_clean
                        ):
                            path_str = ".".join(
                                str(p) for p in path if isinstance(p, (str, int))
                            )
                            joined_name = f"{rhs_clean}.{path_str}"
                            if joined_name in child_process_sinks:
                                child_process_sinks[local_name] = child_process_sinks[
                                    joined_name
                                ]
                            if joined_name in third_party_shell_sinks:
                                third_party_shell_sinks.add(local_name)

                        var_name_norm = self._normalize_property_path(local_name)

                        is_require_cp = re.fullmatch(
                            r"require\(['\"](?:node:)?child_process['\"]\)",
                            rhs_clean,
                        )
                        prop_name = (
                            path[-1] if path and isinstance(path[-1], str) else None
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

                        target_val = self._get_nested_fallback_value(rhs_clean, path)
                        current_taints = tainted_names.union(
                            p for p, _ in active_local_taints
                        )
                        if is_rest and excluded_keys:
                            has_input = self._is_fallback_rest_tainted(
                                rhs_clean, excluded_keys, current_taints
                            )
                        elif isinstance(target_val, list):
                            has_input = any(
                                self._js_has_external_input(item, current_taints)
                                for item in target_val
                            )
                        elif target_val is not None:
                            has_input = self._js_has_external_input(
                                target_val, current_taints
                            )
                        else:
                            if (
                                rhs_clean.startswith("{") and rhs_clean.endswith("}")
                            ) or (
                                rhs_clean.startswith("[") and rhs_clean.endswith("]")
                            ):
                                has_input = False
                            else:
                                has_input = self._js_has_external_input(
                                    rhs, current_taints
                                )

                        if not has_input and default_val is not None:
                            default_may_apply = target_val is None or (
                                isinstance(target_val, str)
                                and (
                                    not target_val.strip()
                                    or self._js_is_static_undefined(target_val)
                                )
                            )
                            if default_may_apply:
                                has_input = self._js_has_external_input(
                                    default_val, current_taints
                                )

                        if has_input:
                            tainted_names.add(var_name_norm)
                else:
                    var_name = var_names_str
                    var_name_norm = self._normalize_property_path(var_name)
                    if rhs_clean.startswith("{") and rhs_clean.endswith("}"):
                        inner = rhs_clean[1:-1]
                        for part in self._split_array_literal_elements(inner):
                            part = part.strip()
                            if part.startswith("..."):
                                arg = part[3:].strip()
                                orig_name = self._get_child_process_original_name(
                                    arg, child_process_sinks
                                )
                                if orig_name:
                                    child_process_sinks[var_name_norm] = orig_name
                                if arg in third_party_shell_sinks:
                                    third_party_shell_sinks[var_name_norm] = True
                                continue

                            pair_info = self._split_fallback_pair(part)
                            k_name = None
                            v_text = None
                            if pair_info:
                                k_name = self._normalize_static_property_key(
                                    pair_info[0]
                                )
                                v_text = pair_info[1].strip()
                            else:
                                if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
                                    k_name = part
                                    v_text = part

                            if k_name and v_text:
                                if self._is_child_process_alias_assignment(
                                    v_text, child_process_sinks
                                ):
                                    orig_name = self._get_child_process_original_name(
                                        v_text, child_process_sinks
                                    )
                                    if orig_name:
                                        child_process_sinks[
                                            f"{var_name_norm}.{k_name}"
                                        ] = orig_name
                                if v_text in third_party_shell_sinks:
                                    third_party_shell_sinks.add(
                                        f"{var_name_norm}.{k_name}"
                                    )
                    else:
                        orig_name = self._get_child_process_original_name(
                            rhs_clean, child_process_sinks
                        )
                        if orig_name:
                            child_process_sinks[var_name_norm] = orig_name
                    if self._js_options_enable_shell(rhs_clean):
                        shell_true_option_names.add(var_name_norm)

                    current_taints = tainted_names.union(
                        p for p, _ in active_local_taints
                    )
                    has_input = self._js_has_external_input(rhs, current_taints)
                    if has_input:
                        tainted_names.add(var_name_norm)

            current_taints = tainted_names.union(p for p, _ in active_local_taints)
            if not self._js_has_external_input(stripped, current_taints):
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
                    current_taints = tainted_names.union(
                        p for p, _ in active_local_taints
                    )
                    if not self._js_has_external_input(call_text, current_taints):
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
                current_taints = tainted_names.union(p for p, _ in active_local_taints)
                if not self._js_has_external_input(call_text, current_taints):
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
                        if name in third_party_shell_sinks:
                            continue
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
                    current_taints = tainted_names.union(
                        p for p, _ in active_local_taints
                    )
                    if not self._js_has_external_input(call_text, current_taints):
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
                    current_taints = tainted_names.union(
                        p for p, _ in active_local_taints
                    )
                    if not self._js_has_external_input(call_text, current_taints):
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
            r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"]shelljs['\"]\s*\)",
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
            r"(?<![\w$.])(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"]shelljs['\"]\s*\)",
            r"import\s+(?:\*\s+as\s+)?([A-Za-z_$][\w$]*)\s+from\s+['\"]shelljs['\"]",
        )
        for pattern in namespace_patterns:
            for namespace_match in re.finditer(pattern, text):
                sinks.add(f"{namespace_match.group(1)}.exec")

    @staticmethod
    def _member_owner_name(text_before_member: str) -> Optional[str]:
        match = re.search(
            r"(?:(?:\(\s*)?([A-Za-z_$][\w$]*)(?:\s*\))?|require\s*\(\s*['\"]((?:node:)?child_process)['\"]\s*\))\s*!?\s*\??\.\s*$",
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

    @staticmethod
    def _split_outer_assignment(text: str) -> Optional[Tuple[str, str]]:
        brace_level = 0
        bracket_level = 0
        paren_level = 0
        in_string = None
        escaped = False

        for idx, char in enumerate(text):
            if escaped:
                escaped = False
                continue
            if in_string:
                if char == "\\":
                    escaped = True
                elif char == in_string:
                    in_string = None
                continue
            if char in {"'", '"', "`"}:
                in_string = char
                continue
            if char == "{":
                brace_level += 1
            elif char == "}":
                if brace_level > 0:
                    brace_level -= 1
            elif char == "[":
                bracket_level += 1
            elif char == "]":
                if bracket_level > 0:
                    bracket_level -= 1
            elif char == "(":
                paren_level += 1
            elif char == ")":
                if paren_level > 0:
                    paren_level -= 1
            elif char == "=":
                if brace_level == 0 and bracket_level == 0 and paren_level == 0:
                    return text[:idx].strip(), text[idx + 1 :].strip()
        return None

    def _is_child_process_sink_call(
        self, callee: str, child_process_sinks: Dict[str, str]
    ) -> Optional[str]:
        callee_clean = callee.replace("?.", ".")
        callee_clean = re.sub(
            r"^require\(['\"](?:node:)?child_process['\"]\)(?=\.)",
            "child_process",
            callee_clean,
        )
        callee_clean = re.sub(
            r"^\(\s*([A-Za-z_$][\w$]*)\s*\)(?=!?\.)", r"\1", callee_clean
        )
        callee_clean = re.sub(r"(?<=[\w$])!(?=\.)", "", callee_clean)

        callee_tail = callee_clean.split(".")[-1]

        is_known_sink = (
            callee_clean in child_process_sinks or callee_tail in child_process_sinks
        )
        if not is_known_sink and callee_tail in self._CHILD_PROCESS_NAMES:
            if "." in callee_clean:
                obj_name = callee_clean.split(".")[0]
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
            return None

        if "." in callee_clean:
            obj_name = callee_clean.split(".")[0]
            is_cp_module = child_process_sinks.get(
                obj_name
            ) == "child_process" or obj_name in {"child_process", "cp"}
            if is_cp_module:
                resolved_sink = callee_tail
            else:
                resolved_sink = child_process_sinks.get(callee_tail) or callee_tail
        else:
            resolved_sink = child_process_sinks.get(callee_tail) or callee_tail

        return resolved_sink

    @staticmethod
    def _strip_type_annotation(text: str) -> str:
        brace_level = 0
        bracket_level = 0
        paren_level = 0
        in_string = None
        escaped = False

        for idx, char in enumerate(text):
            if escaped:
                escaped = False
                continue
            if in_string:
                if char == "\\":
                    escaped = True
                elif char == in_string:
                    in_string = None
                continue
            if char in {"'", '"', "`"}:
                in_string = char
                continue
            if char == "{":
                brace_level += 1
            elif char == "}":
                if brace_level > 0:
                    brace_level -= 1
            elif char == "[":
                bracket_level += 1
            elif char == "]":
                if bracket_level > 0:
                    bracket_level -= 1
            elif char == "(":
                paren_level += 1
            elif char == ")":
                if paren_level > 0:
                    paren_level -= 1
            elif char == ":":
                if brace_level == 0 and bracket_level == 0 and paren_level == 0:
                    return text[:idx].strip()
        return text.strip()

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
                if (
                    (paren_level == 0 and brace_level == 0 and bracket_level == 0)
                    or (
                        char == "("
                        and paren_level == 1
                        and brace_level == 0
                        and bracket_level == 0
                    )
                    or (
                        char == "{"
                        and paren_level == 0
                        and brace_level == 1
                        and bracket_level == 0
                    )
                    or (
                        char == "["
                        and paren_level == 0
                        and brace_level == 0
                        and bracket_level == 1
                    )
                ):
                    is_assign_candidate = True
                else:
                    is_assign_candidate = False
                if is_assign_candidate:
                    assign_match = re.match(
                        r"(\(\s*(?:\{[^;]*?\}|\[[^;]*?\])\s*\)|(?:\{[^;]*?\}|\[[^;]*?\])|[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*|\[\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`)\s*\])*)\s*(?:\+|-|\*|/|%|&|\||\^|<<|>>>?|\?\?|\|\||&&)?=(?!=)",
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
                        current_var_name = assign_match.group(1).strip()
                        if current_var_name.startswith(
                            "("
                        ) and current_var_name.endswith(")"):
                            current_var_name = current_var_name[1:-1].strip()
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
                        inner_var_name = assign_match.group(1).strip()
                        if inner_var_name.startswith("(") and inner_var_name.endswith(
                            ")"
                        ):
                            inner_var_name = inner_var_name[1:-1].strip()
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

    def _split_fallback_pair(self, part: str) -> Optional[Tuple[str, str]]:
        brace_depth = 0
        bracket_depth = 0
        paren_depth = 0
        in_string = None
        for idx in range(len(part)):
            char = part[idx]
            if in_string:
                if char == in_string:
                    in_string = None
                continue
            if char in {"'", '"', "`"}:
                in_string = char
                continue
            if char == "{":
                brace_depth += 1
            elif char == "}":
                brace_depth = max(0, brace_depth - 1)
            elif char == "[":
                bracket_depth += 1
            elif char == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth = max(0, paren_depth - 1)
            elif (
                char == ":"
                and brace_depth == 0
                and bracket_depth == 0
                and paren_depth == 0
            ):
                return part[:idx].strip(), part[idx + 1 :].strip()
        return None

    def _expand_destructuring(
        self, node: Any, current_path: List[Union[str, int]], src_bytes: bytes
    ) -> List[
        Tuple[str, List[Union[str, int]], bool, Optional[Set[str]], Optional[Any]]
    ]:
        results = []
        node_type = getattr(node, "type", "")
        if node_type == "object_pattern":
            local_keys = set()
            for child in getattr(node, "named_children", []):
                c_type = getattr(child, "type", "")
                if c_type == "pair":
                    key_node = ts_child_by_field_name(child, "key")
                    if key_node:
                        p_name = ts_node_text(src_bytes, key_node).strip()
                        p_name = self._normalize_static_property_key(p_name)
                        local_keys.add(p_name)
                elif c_type != "rest_pattern":
                    p_name = ts_node_text(src_bytes, child).strip()
                    if c_type == "assignment_pattern":
                        left_node = ts_child_by_field_name(child, "left")
                        if left_node:
                            p_name = ts_node_text(src_bytes, left_node).strip()
                    local_keys.add(p_name)
            for child in getattr(node, "named_children", []):
                c_type = getattr(child, "type", "")
                if c_type == "pair":
                    key_node = ts_child_by_field_name(child, "key")
                    val_node = ts_child_by_field_name(child, "value")
                    if key_node and val_node:
                        p_name = ts_node_text(src_bytes, key_node).strip()
                        p_name = self._normalize_static_property_key(p_name)
                        results.extend(
                            self._expand_destructuring(
                                val_node, current_path + [p_name], src_bytes
                            )
                        )
                elif c_type == "assignment_pattern":
                    results.extend(
                        self._expand_destructuring(child, current_path, src_bytes)
                    )
                elif c_type == "rest_pattern":
                    local_name = ts_node_text(src_bytes, child).strip()
                    if local_name.startswith("..."):
                        local_name = local_name[3:].strip()
                    results.append((local_name, current_path, True, local_keys, None))
                else:
                    p_name = ts_node_text(src_bytes, child).strip()
                    results.append((p_name, current_path + [p_name], False, None, None))
        elif node_type == "array_pattern":
            elements = getattr(node, "children", [])
            idx = 0
            for child in elements:
                c_type = getattr(child, "type", "")
                if c_type == ",":
                    idx += 1
                    continue
                if c_type in {"[", "]"}:
                    continue
                actual_child = child
                if c_type == "assignment_pattern":
                    results.extend(
                        self._expand_destructuring(
                            child, current_path + [idx], src_bytes
                        )
                    )
                else:
                    actual_type = getattr(actual_child, "type", "")
                    if actual_type in {"object_pattern", "array_pattern"}:
                        results.extend(
                            self._expand_destructuring(
                                actual_child, current_path + [idx], src_bytes
                            )
                        )
                    elif c_type == "rest_pattern" or actual_type == "rest_pattern":
                        local_name = ts_node_text(src_bytes, actual_child).strip()
                        if local_name.startswith("..."):
                            local_name = local_name[3:].strip()
                        results.append(
                            (
                                local_name,
                                current_path + [slice(idx, None)],
                                False,
                                None,
                                None,
                            )
                        )
                    else:
                        local_name = ts_node_text(src_bytes, actual_child).strip()
                        results.append(
                            (local_name, current_path + [idx], False, None, None)
                        )
        elif node_type == "assignment_pattern":
            left_node = ts_child_by_field_name(node, "left")
            right_node = ts_child_by_field_name(node, "right")
            if left_node:
                sub_results = self._expand_destructuring(
                    left_node, current_path, src_bytes
                )
                for local_name, path, is_rest, excluded_keys, _ in sub_results:
                    results.append(
                        (local_name, path, is_rest, excluded_keys, right_node)
                    )
        else:
            local_name = ts_node_text(src_bytes, node).strip()
            results.append((local_name, current_path, False, None, None))
        return results

    def _get_spread_argument(self, node: Any) -> Optional[Any]:
        arg = ts_child_by_field_name(node, "argument")
        if arg is None:
            named = getattr(node, "named_children", [])
            if named:
                arg = named[0]
        return arg

    def _get_nested_property_value(
        self, right_node: Any, path: List[Union[str, int, slice]], src_bytes: bytes
    ) -> Any:
        curr = right_node
        for p in path:
            if curr is None:
                return None
            if isinstance(p, slice):
                curr_type = getattr(curr, "type", "")
                if curr_type == "array":

                    def _flatten_array_node(node):
                        result = []
                        for child in getattr(node, "children", []):
                            c_type = getattr(child, "type", "")
                            if c_type in {",", "[", "]"}:
                                continue
                            if c_type == "spread_element":
                                arg = self._get_spread_argument(child)
                                if (
                                    arg is not None
                                    and getattr(arg, "type", "") == "array"
                                ):
                                    result.extend(_flatten_array_node(arg))
                                else:
                                    result.append(child)
                            else:
                                result.append(child)
                        return result

                    flat_elements = _flatten_array_node(curr)
                    start = p.start if p.start is not None else 0
                    curr = flat_elements[start:]
                else:
                    return None
                continue
            if isinstance(curr, list):
                return None
            curr_type = getattr(curr, "type", "")
            if isinstance(p, str):
                if curr_type == "object":
                    found = None
                    for child in getattr(curr, "named_children", []):
                        c_type = getattr(child, "type", "")
                        if c_type == "pair":
                            key_node = ts_child_by_field_name(child, "key")
                            if key_node:
                                key_text = ts_node_text(src_bytes, key_node).strip()
                                key_norm = self._normalize_static_property_key(key_text)
                                if key_norm == p:
                                    found = ts_child_by_field_name(child, "value")
                        elif c_type == "spread_element":
                            argument = self._get_spread_argument(child)
                            if argument is not None:
                                arg_type = getattr(argument, "type", "")
                                if arg_type == "object":
                                    val = self._get_nested_property_value(
                                        argument, [p], src_bytes
                                    )
                                    if val is not None:
                                        found = val
                                else:
                                    found = argument
                    curr = found
                else:
                    return None
            elif isinstance(p, int):
                if curr_type == "array":
                    flat_elements = []
                    expect_element = True
                    for child in getattr(curr, "children", []):
                        c_type = getattr(child, "type", "")
                        if c_type in {"[", "]"}:
                            continue
                        if c_type == ",":
                            if expect_element:
                                flat_elements.append(None)
                            expect_element = True
                            continue

                        if c_type == "spread_element":
                            argument = self._get_spread_argument(child)
                            if (
                                argument is not None
                                and getattr(argument, "type", "") == "array"
                            ):
                                sub_expect = True
                                sub_elements = []
                                for sc in getattr(argument, "children", []):
                                    sc_type = getattr(sc, "type", "")
                                    if sc_type in {"[", "]"}:
                                        continue
                                    if sc_type == ",":
                                        if sub_expect:
                                            sub_elements.append(None)
                                        sub_expect = True
                                        continue
                                    sub_elements.append(sc)
                                    sub_expect = False
                                flat_elements.extend(sub_elements)
                            else:
                                flat_elements.append(child)
                        else:
                            flat_elements.append(child)
                        expect_element = False

                    if p < len(flat_elements):
                        curr = flat_elements[p]
                        if getattr(curr, "type", "") == "spread_element":
                            argument = self._get_spread_argument(curr)
                            curr = argument if argument is not None else curr
                    else:
                        return None
                else:
                    return None
        return curr

    def _get_fallback_nested_property_value_text(
        self, text: str, path: List[Union[str, int]]
    ) -> Optional[str]:
        curr = text.strip()
        for p in path:
            if isinstance(p, str):
                if curr.startswith("{") and curr.endswith("}"):
                    inner = curr[1:-1]
                    found = False
                    for part in self._split_array_literal_elements(inner):
                        part = part.strip()
                        if not part or part.startswith("..."):
                            continue
                        if "=" in part:
                            part = part.split("=", 1)[0].strip()
                        pair_info = self._split_fallback_pair(part)
                        if pair_info:
                            key = self._normalize_static_property_key(pair_info[0])
                            if key == p:
                                curr = pair_info[1]
                                found = True
                                break
                        else:
                            if part == p:
                                curr = part
                                found = True
                                break
                    if not found:
                        return None
                else:
                    return None
            elif isinstance(p, int):
                if curr.startswith("[") and curr.endswith("]"):
                    inner = curr[1:-1]

                    def _flatten_fallback_array_elements(text_inner: str) -> List[str]:
                        result = []
                        for part in self._split_array_literal_elements(text_inner):
                            part = part.strip()
                            if part.startswith("..."):
                                spread_arg = part[3:].strip()
                                if spread_arg.startswith("[") and spread_arg.endswith(
                                    "]"
                                ):
                                    sub_inner = spread_arg[1:-1]
                                    result.extend(
                                        _flatten_fallback_array_elements(sub_inner)
                                    )
                                else:
                                    result.append(part)
                            else:
                                result.append(part)
                        return result

                    elements = _flatten_fallback_array_elements(inner)
                    if p < len(elements):
                        curr = elements[p].strip()
                        if not curr:
                            return None
                    else:
                        return None
                else:
                    return None
        return curr

    def _is_rest_tainted(
        self,
        right_node: Any,
        excluded_keys: Set[str],
        tainted_names: Set[str],
        src_bytes: bytes,
    ) -> bool:
        if right_node is None or getattr(right_node, "type", "") != "object":
            return False
        for child in getattr(right_node, "named_children", []):
            c_type = getattr(child, "type", "")
            if c_type == "pair":
                key_node = ts_child_by_field_name(child, "key")
                val_node = ts_child_by_field_name(child, "value")
                if key_node and val_node:
                    p_name = ts_node_text(src_bytes, key_node).strip()
                    p_name = self._normalize_static_property_key(p_name)
                    if p_name not in excluded_keys:
                        if self._js_has_external_input(
                            ts_node_text(src_bytes, val_node), tainted_names
                        ):
                            return True
            elif c_type == "spread_element":
                argument = self._get_spread_argument(child)
                if argument is not None:
                    arg_type = getattr(argument, "type", "")
                    if arg_type == "object":
                        if self._is_rest_tainted(
                            argument, excluded_keys, tainted_names, src_bytes
                        ):
                            return True
                    else:
                        arg_text = ts_node_text(src_bytes, argument).strip()
                        if self._js_has_external_input(arg_text, tainted_names):
                            return True
            else:
                p_name = ts_node_text(src_bytes, child).strip()
                if p_name not in excluded_keys:
                    if self._js_has_external_input(p_name, tainted_names):
                        return True
        return False

    def _expand_fallback_destructuring(
        self, pattern_str: str, current_path: List[Union[str, int]]
    ) -> List[
        Tuple[str, List[Union[str, int]], bool, Optional[Set[str]], Optional[str]]
    ]:
        pattern_str = pattern_str.strip()
        results = []
        if pattern_str.startswith("{") and pattern_str.endswith("}"):
            inner = pattern_str[1:-1]
            local_keys = set()
            for part in self._split_array_literal_elements(inner):
                part = part.strip()
                if not part or part.startswith("..."):
                    continue
                if "=" in part:
                    part = part.split("=", 1)[0].strip()
                pair_info = self._split_fallback_pair(part)
                if pair_info:
                    prop_name = self._normalize_static_property_key(pair_info[0])
                else:
                    prop_name = part
                local_keys.add(prop_name)
            for part in self._split_array_literal_elements(inner):
                part = part.strip()
                if not part:
                    continue
                default_val = None
                if "=" in part:
                    part, default_val = part.split("=", 1)
                    part = part.strip()
                    default_val = default_val.strip()
                if part.startswith("..."):
                    local_name = part[3:].strip()
                    results.append(
                        (local_name, current_path, True, local_keys, default_val)
                    )
                else:
                    pair_info = self._split_fallback_pair(part)
                    if pair_info:
                        prop_name = self._normalize_static_property_key(pair_info[0])
                        val_part = pair_info[1].strip()
                        sub_res = self._expand_fallback_destructuring(
                            val_part, current_path + [prop_name]
                        )
                        for (
                            local_name,
                            path,
                            is_rest,
                            excluded_keys,
                            sub_def,
                        ) in sub_res:
                            final_def = sub_def if sub_def is not None else default_val
                            results.append(
                                (local_name, path, is_rest, excluded_keys, final_def)
                            )
                    else:
                        results.append(
                            (part, current_path + [part], False, None, default_val)
                        )
        elif pattern_str.startswith("[") and pattern_str.endswith("]"):
            inner = pattern_str[1:-1]
            idx = 0
            for part in self._split_and_flatten_array_elements(inner):
                part = part.strip()
                if not part:
                    idx += 1
                    continue
                default_val = None
                if "=" in part:
                    part, default_val = part.split("=", 1)
                    part = part.strip()
                    default_val = default_val.strip()
                if part.startswith("..."):
                    local_name = part[3:].strip()
                    results.append(
                        (
                            local_name,
                            current_path + [slice(idx, None)],
                            False,
                            None,
                            default_val,
                        )
                    )
                elif part.startswith("{") or part.startswith("["):
                    results.extend(
                        self._expand_fallback_destructuring(part, current_path + [idx])
                    )
                else:
                    results.append(
                        (part, current_path + [idx], False, None, default_val)
                    )
                idx += 1
        else:
            default_val = None
            if "=" in pattern_str:
                pattern_str, default_val = pattern_str.split("=", 1)
                pattern_str = pattern_str.strip()
                default_val = default_val.strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", pattern_str):
                results.append((pattern_str, current_path, False, None, default_val))
        return results

    def _get_nested_fallback_value(
        self, rhs_str: str, path: List[Union[str, int, slice]]
    ) -> Optional[Union[str, List[str]]]:
        curr = rhs_str.strip()
        for p in path:
            if not curr:
                return None
            if isinstance(p, slice):
                if curr.startswith("[") and curr.endswith("]"):
                    inner = curr[1:-1]
                    flat_elements = self._split_and_flatten_array_elements(inner)
                    start = p.start if p.start is not None else 0
                    curr = [el.strip() for el in flat_elements[start:]]
                else:
                    return None
                continue
            if isinstance(curr, list):
                return None
            if isinstance(p, str):
                if curr.startswith("{") and curr.endswith("}"):
                    inner = curr[1:-1]
                    found = None
                    for part in self._split_array_literal_elements(inner):
                        part = part.strip()
                        if part.startswith("..."):
                            arg = part[3:].strip()
                            if arg.startswith("{") and arg.endswith("}"):
                                val = self._get_nested_fallback_value(arg, [p])
                                if val is not None:
                                    found = val
                            else:
                                found = arg
                        else:
                            pair_info = self._split_fallback_pair(part)
                            if pair_info:
                                key = self._normalize_static_property_key(pair_info[0])
                                if key == p:
                                    found = pair_info[1].strip()
                            else:
                                shorthand = part.strip()
                                if shorthand == p:
                                    found = shorthand
                    curr = found
                else:
                    return None
            elif isinstance(p, int):
                if curr.startswith("[") and curr.endswith("]"):
                    inner = curr[1:-1]
                    flat_elements = self._split_and_flatten_array_elements(inner)

                    if p < len(flat_elements):
                        target = flat_elements[p]
                        if target.startswith("..."):
                            curr = target[3:].strip()
                        else:
                            curr = target
                    else:
                        return None
                else:
                    return None
        return curr

    def _is_fallback_rest_tainted(
        self, rhs_str: str, excluded_keys: Set[str], tainted_names: Set[str]
    ) -> bool:
        rhs_str = rhs_str.strip()
        if not (rhs_str.startswith("{") and rhs_str.endswith("}")):
            return False
        inner = rhs_str[1:-1]
        for part in self._split_array_literal_elements(inner):
            part = part.strip()
            if part.startswith("..."):
                arg = part[3:].strip()
                if arg.startswith("{") and arg.endswith("}"):
                    if self._is_fallback_rest_tainted(
                        arg, excluded_keys, tainted_names
                    ):
                        return True
                else:
                    if self._js_has_external_input(arg, tainted_names):
                        return True
            else:
                pair_info = self._split_fallback_pair(part)
                if pair_info:
                    key = self._normalize_static_property_key(pair_info[0])
                    val = pair_info[1].strip()
                    if key not in excluded_keys:
                        if self._js_has_external_input(val, tainted_names):
                            return True
                else:
                    shorthand = part.strip()
                    if shorthand not in excluded_keys:
                        if self._js_has_external_input(shorthand, tainted_names):
                            return True
        return False

    def _evaluate_js_ts_subtree(
        self,
        root_node: Any,
        target: Path,
        src_bytes: bytes,
        tainted_names: Set[str],
        child_process_sinks: Dict[str, str],
        file_path: Path,
    ) -> List[RiskRecord]:
        records = []
        rel_path = str(file_path.relative_to(target))
        local_sinks = child_process_sinks.copy()

        # subtree 内の関数再帰定義時の二重検知を防止する
        skip_body_node = None

        for node in iter_ts_nodes(root_node):
            if skip_body_node is not None:
                if (
                    node.start_byte >= skip_body_node.start_byte
                    and node.end_byte <= skip_body_node.end_byte
                ):
                    continue
                else:
                    skip_body_node = None

            node_type = getattr(node, "type", "")

            # サブツリー内の入れ子になった関数パラメータデフォルト汚染伝播
            if node_type in {
                "function_declaration",
                "generator_function_declaration",
                "method_definition",
                "arrow_function",
                "function_expression",
            }:
                body_node = ts_child_by_field_name(node, "body")
                if body_node:
                    local_taints = set()
                    params_node = ts_child_by_field_name(node, "parameters")
                    if not params_node:
                        for c in getattr(node, "named_children", []):
                            if getattr(c, "type", "") == "formal_parameters":
                                params_node = c
                                break
                    if params_node:
                        for param in getattr(params_node, "named_children", []):
                            p_type = getattr(param, "type", "")
                            if p_type == "assignment_pattern":
                                p_left = ts_child_by_field_name(param, "left")
                                p_right = ts_child_by_field_name(param, "right")
                                if p_left and p_right:
                                    p_right_text = ts_node_text(src_bytes, p_right)
                                    rhs_tainted = self._js_has_external_input(
                                        p_right_text, tainted_names
                                    )
                                    p_left_type = getattr(p_left, "type", "")
                                    if p_left_type == "identifier":
                                        if rhs_tainted:
                                            p_left_text = ts_node_text(
                                                src_bytes, p_left
                                            ).strip()
                                            local_taints.add(p_left_text)
                                    elif p_left_type in {
                                        "object_pattern",
                                        "array_pattern",
                                    }:
                                        expanded = self._expand_destructuring(
                                            p_left, [], src_bytes
                                        )
                                        for (
                                            local_name,
                                            _,
                                            _,
                                            _,
                                            default_node,
                                        ) in expanded:
                                            if not local_name or not re.fullmatch(
                                                r"[A-Za-z_$][\w$]*", local_name
                                            ):
                                                continue
                                            has_taint = rhs_tainted
                                            if (
                                                not has_taint
                                                and default_node is not None
                                            ):
                                                def_text = ts_node_text(
                                                    src_bytes, default_node
                                                )
                                                has_taint = self._js_has_external_input(
                                                    def_text, tainted_names
                                                )
                                            if has_taint:
                                                local_taints.add(local_name)
                            elif p_type in {"object_pattern", "array_pattern"}:
                                expanded = self._expand_destructuring(
                                    param, [], src_bytes
                                )
                                for (
                                    local_name,
                                    _,
                                    _,
                                    _,
                                    default_node,
                                ) in expanded:
                                    if not local_name or not re.fullmatch(
                                        r"[A-Za-z_$][\w$]*", local_name
                                    ):
                                        continue
                                    if default_node is not None:
                                        def_text = ts_node_text(src_bytes, default_node)
                                        if self._js_has_external_input(
                                            def_text, tainted_names
                                        ):
                                            local_taints.add(local_name)

                    if local_taints:
                        local_tainted_nested = tainted_names.union(local_taints)
                        local_records = self._evaluate_js_ts_subtree(
                            body_node,
                            target,
                            src_bytes,
                            local_tainted_nested,
                            local_sinks,
                            file_path,
                        )
                        if local_records:
                            records.extend(local_records)
                        skip_body_node = body_node
                        continue

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

                    if left_type in {"object_pattern", "array_pattern"}:
                        rhs_tainted = self._js_has_external_input(
                            right_text, tainted_names
                        )
                        expanded = self._expand_destructuring(left, [], src_bytes)
                        for (
                            local_name,
                            path,
                            _,
                            _,
                            _,
                        ) in expanded:
                            if not local_name or not re.fullmatch(
                                r"[A-Za-z_$][\w$]*", local_name
                            ):
                                continue
                            if re.fullmatch(
                                r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", right_clean
                            ):
                                path_str = ".".join(
                                    str(p) for p in path if isinstance(p, (str, int))
                                )
                                joined_name = f"{right_clean}.{path_str}"
                                if joined_name in local_sinks:
                                    local_sinks[local_name] = local_sinks[joined_name]
                            target_node = self._get_nested_property_value(
                                right, path, src_bytes
                            )
                            if isinstance(target_node, list):
                                has_input = any(
                                    self._js_has_external_input(
                                        ts_node_text(src_bytes, item), tainted_names
                                    )
                                    for item in target_node
                                )
                            elif target_node is not None:
                                has_input = self._js_has_external_input(
                                    ts_node_text(src_bytes, target_node),
                                    tainted_names,
                                )
                            else:
                                has_input = rhs_tainted
                            if has_input:
                                tainted_names.add(local_name)
                    else:
                        if re.fullmatch(
                            r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", left_text_norm
                        ):
                            if self._is_child_process_alias_assignment(
                                right_clean, local_sinks
                            ):
                                orig_name = self._get_child_process_original_name(
                                    right_clean, local_sinks
                                )
                                if orig_name:
                                    local_sinks[left_text_norm] = orig_name
                            elif getattr(right, "type", "") == "object":
                                for child in getattr(right, "named_children", []):
                                    if getattr(child, "type", "") == "pair":
                                        key_node = ts_child_by_field_name(child, "key")
                                        val_node = ts_child_by_field_name(
                                            child, "value"
                                        )
                                        if key_node and val_node:
                                            k_name = ts_node_text(
                                                src_bytes, key_node
                                            ).strip()
                                            k_name = (
                                                self._normalize_static_property_key(
                                                    k_name
                                                )
                                            )
                                            v_text = ts_node_text(
                                                src_bytes, val_node
                                            ).strip()
                                            if self._is_child_process_alias_assignment(
                                                v_text, local_sinks
                                            ):
                                                orig_name = self._get_child_process_original_name(
                                                    v_text, local_sinks
                                                )
                                                if orig_name:
                                                    local_sinks[
                                                        f"{left_text_norm}.{k_name}"
                                                    ] = orig_name

                            has_input = self._js_has_external_input(
                                right_text, tainted_names
                            )
                            if has_input:
                                tainted_names.add(left_text_norm)

            if node_type == "call_expression":
                function_node = ts_child_by_field_name(node, "function")
                if function_node:
                    func_text = ts_node_text(src_bytes, function_node).strip()
                    resolved_sink = self._is_child_process_sink_call(
                        func_text, local_sinks
                    )
                    if resolved_sink is not None:
                        call_text = ts_node_text(src_bytes, node)
                        has_external = self._js_has_external_input(
                            call_text, tainted_names
                        )
                        if has_external:
                            sink_node = None
                            if (
                                getattr(function_node, "type", "")
                                == "member_expression"
                            ):
                                sink_node = ts_child_by_field_name(
                                    function_node, "property"
                                )
                            if sink_node is None:
                                sink_node = function_node

                            start_point = (
                                getattr(sink_node, "start_point", (0, 0))
                                if sink_node
                                else getattr(node, "start_point", (0, 0))
                            )
                            node_start_point = getattr(node, "start_point", (0, 0))
                            line = node_start_point[0] + 1
                            col = start_point[1]
                            byte_offset = (
                                getattr(sink_node, "start_byte", 0)
                                if sink_node
                                else getattr(node, "start_byte", 0)
                            )

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
                                    src_bytes[:byte_offset].decode(
                                        "utf-8", errors="replace"
                                    )
                                )
                                records.append(rec)
                            elif resolved_sink in {"execFile", "execFileSync", "fork"}:
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
                                    src_bytes[:byte_offset].decode(
                                        "utf-8", errors="replace"
                                    )
                                )
                                records.append(rec)
                            elif resolved_sink in {"spawn", "spawnSync"}:
                                has_shell_true = (
                                    "shell: true" in call_text
                                    or "shell:true" in call_text
                                )
                                rec = RiskRecord(
                                    rule_id=self.rule_id,
                                    category=self.category,
                                    title=self.title,
                                    severity=Severity.HIGH
                                    if has_shell_true
                                    else Severity.MEDIUM,
                                    file_path=rel_path,
                                    line=line,
                                    message="External input reaches child_process spawn with shell=true"
                                    if has_shell_true
                                    else "External input reaches child_process spawn",
                                )
                                rec._column = col
                                rec._char_offset = len(
                                    src_bytes[:byte_offset].decode(
                                        "utf-8", errors="replace"
                                    )
                                )
                                records.append(rec)
        return records

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for js_file in self._iter_js_ts_files(target):
            records.extend(self._evaluate_js_ts_file(js_file, target))
        return dedupe_records(records)
