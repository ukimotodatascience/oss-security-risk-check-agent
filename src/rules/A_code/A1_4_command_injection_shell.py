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
    ts_node_text,
    line_col_to_offset,
    offset_to_line_col,
)
from src.rules.A_code.A1_4_1_command_injection_shell_sources import ShellSourceMixin


class ShellCommandInjectionDetector(ShellSourceMixin):
    @staticmethod
    def _count_unescaped_braces(text: str) -> int:
        count = 0
        in_string = None
        escaped = False
        for char in text:
            if escaped:
                escaped = False
                continue
            if char == "\\" and in_string != "'":
                escaped = True
                continue
            if in_string:
                if char == in_string:
                    in_string = None
                continue
            if char in {"'", '"', "`"}:
                in_string = char
                continue
            # シェルコメント以降の波括弧は無視する
            if char == "#":
                break
            if char == "{":
                count += 1
            elif char == "}":
                count -= 1
        return count

    rule_id = RULE_ID
    category = CATEGORY
    title = TITLE
    severity = DEFAULT_SEVERITY
    _SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh"}

    def _iter_shell_files(self, target: Path) -> Iterable[Path]:
        """対象ディレクトリ配下の shell script を列挙する。"""
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._SHELL_EXTENSIONS:
                yield p

    def _evaluate_shell_file(self, file_path: Path, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        rel_path = str(file_path.relative_to(target))
        try:
            src = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return records
        tree_sitter_records = self._evaluate_shell_file_with_tree_sitter(
            file_path, target, src
        )
        if tree_sitter_records is not None:
            records.extend(tree_sitter_records)
        tainted_names: Set[str] = set()
        active_local_taints: List[Tuple[str, int, bool]] = []
        current_brace_level = 0
        # local はブロックスコープではなく関数スコープ
        # 関数定義ごとの波括弧レベルをスタックで管理する
        func_brace_stack: List[int] = []
        lines = src.splitlines()
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # 関数定義の検出: name() または function name
            if re.match(r"(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\)", stripped):
                func_brace_stack.append(current_brace_level)

            current_brace_level += self._count_unescaped_braces(stripped)
            if current_brace_level < 0:
                current_brace_level = 0

            # 関数スコープを抜けた場合、スタックからポップ
            while func_brace_stack and current_brace_level <= func_brace_stack[-1]:
                func_brace_stack.pop()

            expired_locals = [
                (param, was_tainted)
                for param, lvl, was_tainted in active_local_taints
                if current_brace_level < lvl
            ]
            for param, was_tainted in expired_locals:
                if was_tainted:
                    # 外側スコープで汚染されていた状態を復元する
                    tainted_names.add(param)
                else:
                    tainted_names.discard(param)

            active_local_taints = [
                (param, lvl, was_tainted)
                for param, lvl, was_tainted in active_local_taints
                if current_brace_level >= lvl
            ]

            stmt_start_idx = line.find(stripped)
            if stmt_start_idx == -1:
                stmt_start_idx = len(line) - len(line.lstrip())

            # local 変数のスコープは関数レベルで管理する
            func_level = (
                func_brace_stack[-1] + 1 if func_brace_stack else current_brace_level
            )
            self._track_shell_taint_from_text(
                stripped, tainted_names, active_local_taints, func_level
            )
            self._track_shell_case_allowlist_from_text(stripped, tainted_names)
            has_external = self._shell_expands_external_input(stripped, tainted_names)
            if not has_external:
                continue

            # 1. eval
            for m in re.finditer("\\beval\\b", stripped):
                call_text = self._get_shell_pipeline_context(stripped, m.start())
                if not self._shell_expands_external_input(call_text, tainted_names):
                    continue
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message="External input reaches shell eval",
                )
                col = stmt_start_idx + m.start()
                rec._column = col
                rec._char_offset = line_col_to_offset(src, i, col)
                records.append(rec)

            # 2. sh, bash, zsh, ksh -c (xargs/find 含む)
            for m in re.finditer(r"\b(?:sh|bash|zsh|ksh)\s+-c\b", stripped):
                prefix = self._get_shell_prefix_context(stripped, m.start())
                is_xargs_find = bool(re.search(r"\b(?:xargs|find)\b", prefix))

                call_text = self._get_shell_pipeline_context(stripped, m.start())
                if not self._shell_expands_external_input(call_text, tainted_names):
                    continue

                msg = (
                    "External input reaches xargs/find shell -c execution"
                    if is_xargs_find
                    else "External input reaches shell -c execution"
                )
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message=msg,
                )
                col = stmt_start_idx + m.start()
                rec._column = col
                rec._char_offset = line_col_to_offset(src, i, col)
                records.append(rec)

            # 3. backtick command substitution
            for m in re.finditer("`[^`]*\\$[^`]*`", stripped):
                call_text = m.group(0)
                if not self._shell_expands_external_input(call_text, tainted_names):
                    continue
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message="External input reaches backtick command substitution",
                )
                col = stmt_start_idx + m.start()
                rec._column = col
                rec._char_offset = line_col_to_offset(src, i, col)
                records.append(rec)

            # 4. $() command substitution
            for m in re.finditer("\\$\\([^)]*\\$[^)]*\\)", stripped):
                call_text = m.group(0)
                if not self._shell_expands_external_input(call_text, tainted_names):
                    continue
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message="External input reaches $() command substitution",
                )
                col = stmt_start_idx + m.start()
                rec._column = col
                rec._char_offset = line_col_to_offset(src, i, col)
                records.append(rec)

            # 5. source
            source_patterns = [
                "\\b(?:source|\\.)\\s+[^#;]*\\$",
                "\\b(?:source|\\.)\\s+[^#;]*(?:\\$\\{?[A-Za-z_][A-Za-z0-9_]*\\}?|\\$[0-9@*])",
            ]
            for pattern in source_patterns:
                for m in re.finditer(pattern, stripped):
                    call_text = self._get_shell_statement_context(stripped, m.start())
                    if not self._shell_expands_external_input(call_text, tainted_names):
                        continue
                    rec = RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=i,
                        message="External input reaches shell source execution",
                    )
                    col = stmt_start_idx + m.start()
                    rec._column = col
                    rec._char_offset = line_col_to_offset(src, i, col)
                    records.append(rec)

            # 7. controls command name
            if self._line_starts_with_tainted_command(stripped, tainted_names):
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message="External input controls command name execution",
                )
                col = stmt_start_idx
                rec._column = col
                rec._char_offset = line_col_to_offset(src, i, col)
                records.append(rec)

            # 8. here-string
            for m in re.finditer("\\b(?:sh|bash|zsh|ksh)\\s+<<<\\s*", stripped):
                call_text = self._get_shell_statement_context(stripped, m.start())
                if not self._shell_expands_external_input(call_text, tainted_names):
                    continue
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message="External input reaches shell here-string execution",
                )
                col = stmt_start_idx + m.start()
                rec._column = col
                rec._char_offset = line_col_to_offset(src, i, col)
                records.append(rec)
        return dedupe_records(records)

    @staticmethod
    def _line_starts_with_tainted_command(line: str, tainted_names: Set[str]) -> bool:
        for name in tainted_names:
            if re.search(
                rf'^(?:command\s+|env\s+)?(?:"?\$(?:\{{)?{re.escape(name)}(?:\}})?"?)(?:\s|$)',
                line,
            ):
                return True
        return False

    def _evaluate_shell_file_with_tree_sitter(
        self, file_path: Path, target: Path, src: str
    ) -> Optional[List[RiskRecord]]:
        """tree-sitter-bash が利用可能な場合、Shell の危険構文を構文木から補助検出する。"""
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
        active_local_taints: List[Tuple[str, int, bool]] = []
        current_brace_level = 0
        last_byte = 0
        interesting_types = {
            "command",
            "command_substitution",
            "process_substitution",
            "redirected_statement",
            "variable_assignment",
        }
        nodes = sorted(
            [
                n
                for n in iter_ts_nodes(root)
                if getattr(n, "type", "") in interesting_types
            ],
            key=lambda n: (getattr(n, "start_byte", 0), getattr(n, "end_byte", 0)),
        )
        for node in nodes:
            start_byte = getattr(node, "start_byte", 0)
            if start_byte > last_byte:
                between_text = src_bytes[last_byte:start_byte].decode(
                    "utf-8", errors="replace"
                )
                current_brace_level += self._count_unescaped_braces(between_text)
                if current_brace_level < 0:
                    current_brace_level = 0
                expired_locals = [
                    (param, was_tainted)
                    for param, lvl, was_tainted in active_local_taints
                    if current_brace_level < lvl
                ]
                for param, was_tainted in expired_locals:
                    if not was_tainted:
                        tainted_names.discard(param)
                active_local_taints = [
                    (param, lvl, was_tainted)
                    for param, lvl, was_tainted in active_local_taints
                    if current_brace_level >= lvl
                ]
            last_byte = getattr(node, "end_byte", start_byte)

            text = ts_node_text(src_bytes, node).strip()
            if not text or text.startswith("#"):
                continue
            start_point = getattr(node, "start_point", (0, 0))
            line = start_point[0] + 1
            col = start_point[1]
            self._track_shell_taint_from_text(
                text, tainted_names, active_local_taints, current_brace_level
            )
            self._track_shell_case_allowlist_from_text(text, tainted_names)
            byte_offset = getattr(node, "start_byte", 0)
            context_text = self._get_ts_pipeline_text(node, src_bytes)
            if not self._shell_expands_external_input(context_text, tainted_names):
                continue
            if re.search("\\beval\\b", text):
                eval_match = re.search(r"\beval\b", text)
                eval_sub_bytes = (
                    text[: eval_match.start()].encode("utf-8") if eval_match else b""
                )
                target_byte_offset = byte_offset + len(eval_sub_bytes)
                char_offset = len(
                    src_bytes[:target_byte_offset].decode("utf-8", errors="replace")
                )
                line_num, col_num = offset_to_line_col(src, char_offset)
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=line_num,
                    message="External input reaches shell eval",
                )
                rec._column = col_num
                rec._char_offset = char_offset
                records.append(rec)
                continue
            if re.search("\\b(?:sh|bash|zsh|ksh)\\s+-c\\b", text):
                sh_match = re.search(r"\b(?:sh|bash|zsh|ksh)\s+-c\b", text)
                sh_sub_bytes = (
                    text[: sh_match.start()].encode("utf-8") if sh_match else b""
                )
                target_byte_offset = byte_offset + len(sh_sub_bytes)
                char_offset = len(
                    src_bytes[:target_byte_offset].decode("utf-8", errors="replace")
                )
                line_num, col_num = offset_to_line_col(src, char_offset)
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=line_num,
                    message="External input reaches shell -c execution",
                )
                rec._column = col_num
                rec._char_offset = char_offset
                records.append(rec)
                continue
            is_cmd_sub = getattr(node, "type", "") == "command_substitution"
            if is_cmd_sub:
                is_backtick = False
                if text.startswith("`") or text.endswith("`"):
                    is_backtick = True
                msg = (
                    "External input reaches backtick command substitution"
                    if is_backtick
                    else "External input reaches $() command substitution"
                )
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=line,
                    message=msg,
                )
                rec._column = col
                rec._char_offset = len(
                    src_bytes[:byte_offset].decode("utf-8", errors="replace")
                )
                records.append(rec)
        for r in records:
            r._from_ts = True
        return records

    @staticmethod
    def _get_shell_statement_context(text: str, start_idx: int) -> str:
        in_string = None
        escaped = False
        paren_level = 0
        brace_level = 0
        for idx in range(start_idx, len(text)):
            char = text[idx]
            if escaped:
                escaped = False
                continue
            if char == "\\" and in_string != "'":
                escaped = True
                continue
            if in_string:
                if char == in_string:
                    in_string = None
                continue
            if char in {"'", '"', "`"}:
                in_string = char
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
            if char in {";", "|", "&"}:
                if paren_level > 0 or brace_level > 0:
                    continue
                if char == "&":
                    if (idx > 0 and text[idx - 1] in {">", "<"}) or (
                        idx + 1 < len(text) and text[idx + 1] == ">"
                    ):
                        continue
                return text[start_idx:idx]
        return text[start_idx:]

    @staticmethod
    def _get_shell_pipeline_context(text: str, target_idx: int) -> str:
        segment_start = 0
        in_string = None
        escaped = False
        paren_level = 0
        brace_level = 0
        idx = 0
        while idx < len(text):
            char = text[idx]
            if escaped:
                escaped = False
                idx += 1
                continue
            if char == "\\" and in_string != "'":
                escaped = True
                idx += 1
                continue
            if in_string:
                if char == in_string:
                    in_string = None
                idx += 1
                continue
            if char in {"'", '"', "`"}:
                in_string = char
                idx += 1
                continue
            if char == "(":
                paren_level += 1
            elif char == ")" and paren_level:
                paren_level -= 1
            elif char == "{":
                brace_level += 1
            elif char == "}" and brace_level:
                brace_level -= 1
            if paren_level == 0 and brace_level == 0:
                delimiter_length = 0
                if char == ";":
                    delimiter_length = 1
                elif text[idx : idx + 2] in {"&&", "||"}:
                    delimiter_length = 2
                if delimiter_length:
                    if idx >= target_idx:
                        return text[segment_start:idx]
                    segment_start = idx + delimiter_length
                    idx += delimiter_length
                    continue
            idx += 1
        return text[segment_start:]

    @staticmethod
    def _get_ts_pipeline_text(node, src_bytes: bytes) -> str:
        curr = node
        while (
            curr.parent is not None and getattr(curr.parent, "type", "") == "pipeline"
        ):
            curr = curr.parent
        return ts_node_text(src_bytes, curr).strip()

    @staticmethod
    def _get_shell_prefix_context(text: str, match_start: int) -> str:
        last_delim_idx = -1
        in_string = None
        escaped = False
        paren_level = 0
        brace_level = 0
        for idx in range(match_start):
            char = text[idx]
            if escaped:
                escaped = False
                continue
            if char == "\\" and in_string != "'":
                escaped = True
                continue
            if in_string:
                if char == in_string:
                    in_string = None
                continue
            if char in {"'", '"', "`"}:
                in_string = char
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
            if char in {";", "|", "&"}:
                if paren_level > 0 or brace_level > 0:
                    continue
                if char == "&":
                    if (idx > 0 and text[idx - 1] in {">", "<"}) or (
                        idx + 1 < len(text) and text[idx + 1] == ">"
                    ):
                        continue
                last_delim_idx = idx
        return text[last_delim_idx + 1 : match_start]

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for shell_file in self._iter_shell_files(target):
            records.extend(self._evaluate_shell_file(shell_file, target))
        return dedupe_records(records)
