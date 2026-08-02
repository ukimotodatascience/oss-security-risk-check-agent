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
        for node in iter_ts_nodes(root):
            node_type = getattr(node, "type", "")
            text = ts_node_text(src_bytes, node)
            if node_type in {
                "import_statement",
                "lexical_declaration",
                "variable_declaration",
            }:
                self._register_child_process_imports(text, child_process_sinks)
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
                    if obj_name in {"child_process", "cp"} or (
                        child_process_sinks and obj_name in child_process_sinks
                    ):
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
            if callee_tail in {"exec", "execSync"}:
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
            if callee_tail in {"execFile", "execFileSync", "fork"}:
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
            if callee_tail in {"spawn", "spawnSync"}:
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
        shell_true_option_names: Set[str] = set()
        lines = src.splitlines()
        raw_lines = src.splitlines(keepends=True)
        statements: List[Tuple[int, str, str, int]] = []
        buffer = ""
        raw_buffer = ""
        start_line = 1
        curr_raw_offset = 0
        stmt_start_offset = 0
        for i, line in enumerate(lines, start=1):
            comment_removed = self._remove_line_comments(line)
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
        for i, stripped, raw_stmt, stmt_start_offset in statements:
            self._register_child_process_imports(stripped, child_process_sinks)
            m = re.search(
                "\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(.+)$", stripped
            )
            if m:
                (var_name, rhs) = (m.group(1), m.group(2))
                rhs_clean = rhs.rstrip(";").strip()
                orig_name = self._get_child_process_original_name(
                    rhs_clean, child_process_sinks
                )
                if orig_name:
                    child_process_sinks[var_name] = orig_name
                if self._js_options_enable_shell(rhs_clean):
                    shell_true_option_names.add(var_name)
                if self._js_has_external_input(rhs, tainted_names):
                    tainted_names.add(var_name)

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
                    prefix_match = re.search(r"([\w$]+)\.\s*$", stripped[: m.start()])
                    if prefix_match:
                        obj_name = prefix_match.group(1)
                        is_valid = obj_name in {"child_process", "cp"}
                        if not is_valid:
                            if child_process_sinks:
                                is_valid = (obj_name in child_process_sinks) or (
                                    child_process_sinks.get(obj_name) == "child_process"
                                )
                        if not is_valid:
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
            for m, name in third_party_matches:
                if name == "exec":
                    matched_str = m.group(0)
                    if "." in matched_str:
                        obj_name = matched_str.split(".")[0].strip()
                        if obj_name in {"child_process", "cp"} or (
                            child_process_sinks and obj_name in child_process_sinks
                        ):
                            continue
                    else:
                        prefix_match = re.search(
                            r"([\w$]+)\.\s*$", stripped[: m.start()]
                        )
                        if prefix_match:
                            obj_name = prefix_match.group(1)
                            if obj_name in {"child_process", "cp"} or (
                                child_process_sinks and obj_name in child_process_sinks
                            ):
                                continue
                        else:
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
                    prefix_match = re.search(r"([\w$]+)\.\s*$", stripped[: m.start()])
                    if prefix_match:
                        obj_name = prefix_match.group(1)
                        is_valid = obj_name in {"child_process", "cp"}
                        if not is_valid:
                            if child_process_sinks:
                                is_valid = (obj_name in child_process_sinks) or (
                                    child_process_sinks.get(obj_name) == "child_process"
                                )
                        if not is_valid:
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
                    prefix_match = re.search(r"([\w$]+)\.\s*$", stripped[: m.start()])
                    if prefix_match:
                        obj_name = prefix_match.group(1)
                        is_valid = obj_name in {"child_process", "cp"}
                        if not is_valid:
                            if child_process_sinks:
                                is_valid = (obj_name in child_process_sinks) or (
                                    child_process_sinks.get(obj_name) == "child_process"
                                )
                        if not is_valid:
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
    def _get_argument_list_text(text: str, start_paren_idx: int) -> str:
        paren_count = 0
        in_string = None
        in_block_comment = False
        in_line_comment = False
        in_regex = False
        in_regex_class = False
        escaped = False

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

            if in_string:
                if char == "\\":
                    escaped = True
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
                    }
                    regex_start_keywords = {
                        "return",
                        "yield",
                        "typeof",
                        "void",
                        "delete",
                        "throw",
                        "default",
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
    def _remove_line_comments(line: str) -> str:
        in_string = None
        in_block_comment = False
        in_regex = False
        in_regex_class = False
        escaped = False
        idx = 0
        while idx < len(line):
            char = line[idx]
            if in_block_comment:
                if char == "*" and idx + 1 < len(line) and line[idx + 1] == "/":
                    in_block_comment = False
                    idx += 2
                else:
                    idx += 1
                continue
            if escaped:
                escaped = False
                idx += 1
                continue
            if in_string:
                if char == "\\":
                    escaped = True
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
            if char == "/" and idx + 1 < len(line):
                next_char = line[idx + 1]
                if next_char == "*":
                    in_block_comment = True
                    idx += 2
                    continue
                elif next_char == "/":
                    return line[:idx]
                else:
                    # 正規表現リテラルの開始判定
                    prev_token = ""
                    p_idx = idx - 1
                    while p_idx >= 0 and line[p_idx].isspace():
                        p_idx -= 1
                    if p_idx >= 0:
                        if line[p_idx].isalnum() or line[p_idx] in {"_", "$"}:
                            end_p = p_idx
                            while p_idx >= 0 and (
                                line[p_idx].isalnum() or line[p_idx] in {"_", "$"}
                            ):
                                p_idx -= 1
                            prev_token = line[p_idx + 1 : end_p + 1]
                        else:
                            prev_token = line[p_idx]

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
                    }
                    regex_start_keywords = {
                        "return",
                        "yield",
                        "typeof",
                        "void",
                        "delete",
                        "throw",
                        "default",
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
            idx += 1
        return line

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

        for line in raw_lines:
            comment_removed = JsTsCommandInjectionDetector._remove_line_comments(line)
            stripped_line = comment_removed.strip()
            if not stripped_line:
                raw_offset += len(line)
                continue

            left_spaces = len(line) - len(line.lstrip())
            line_start_raw = raw_offset + left_spaces

            if has_prev:
                stripped_map.append(raw_offset - 1 if raw_offset > 0 else 0)

            for j in range(len(stripped_line)):
                stripped_map.append(line_start_raw + j)

            has_prev = True
            raw_offset += len(line)

        return stripped_map

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for js_file in self._iter_js_ts_files(target):
            records.extend(self._evaluate_js_ts_file(js_file, target))
        return dedupe_records(records)
