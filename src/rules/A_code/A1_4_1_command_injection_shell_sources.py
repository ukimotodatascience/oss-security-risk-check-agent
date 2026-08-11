import re
from typing import Set, Optional


class ShellSourceMixin:
    @staticmethod
    def _shell_expands_external_input(line: str, tainted_names: Set[str]) -> bool:
        if re.search(r"\$[0-9@*]", line) or re.search(r"\$\{[0-9]+\}", line):
            return True

        for name in tainted_names:
            if re.search(rf"\$(?:\{{)?{re.escape(name)}(?:\}})?\b", line):
                return True
        return False

    def _track_shell_taint_from_text(self, text: str, tainted_names: Set[str]) -> None:
        read_match = re.search(r"\bread\b(?:\s+-\w+)*\s+([A-Za-z_][A-Za-z0-9_]*)", text)
        if read_match:
            tainted_names.add(read_match.group(1))

        assign_match = re.search(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$", text)
        if assign_match:
            var_name, rhs = assign_match.group(1), assign_match.group(2)
            if self._shell_expands_external_input(rhs, tainted_names):
                tainted_names.add(var_name)

        assignment_pattern = re.compile(
            r"([A-Za-z_][A-Za-z0-9_]*)=((?:\$\([^)]*\)|'[^']*'|\"[^\"]*\"|`[^`]*`|[^\s;'\"`])+)(?:\s+|;\s*|$)"
        )
        for statement in self._split_shell_statements(text):
            statement = statement.strip()
            printf_match = re.match(
                r"^printf\s+-v\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$", statement
            )
            if printf_match and self._shell_expands_external_input(
                printf_match.group(2), tainted_names
            ):
                tainted_names.add(printf_match.group(1))
            position = self._shell_assignment_start_position(statement)
            while position < len(statement):
                m = assignment_pattern.match(statement, position)
                if m is None:
                    break
                var_name, rhs = m.group(1), m.group(2)
                if self._shell_expands_external_input(rhs, tainted_names):
                    tainted_names.add(var_name)
                position = m.end()

    @staticmethod
    def _split_shell_statements(text: str):
        statements = []
        start = 0
        in_string = None
        escaped = False
        paren_depth = 0
        for idx, char in enumerate(text):
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
                paren_depth += 1
                continue
            if char == ")" and paren_depth:
                paren_depth -= 1
                continue
            if paren_depth:
                continue
            pair = text[idx : idx + 2]
            is_background_separator = (
                char == "&"
                and (idx == 0 or text[idx - 1] not in {"<", ">", "&"})
                and (idx + 1 == len(text) or text[idx + 1] not in {"&", ">"})
            )
            is_separator = (
                char == ";" or pair in {"&&", "||"} or is_background_separator
            )
            if is_separator:
                statements.append(text[start:idx])
                start = idx + (2 if pair in {"&&", "||"} else 1)
        statements.append(text[start:])
        return statements

    @staticmethod
    def _shell_assignment_start_position(statement: str) -> int:
        offset = 0
        is_after_case_in = False
        while True:
            # 先頭の空白を読み飛ばす
            while offset < len(statement) and statement[offset].isspace():
                offset += 1

            if offset >= len(statement):
                break

            # { の読み飛ばし
            m = re.match(r"^(?:\{\s*)+", statement[offset:])
            if m:
                offset += m.end()
                is_after_case_in = False
                continue
            # 制御キーワード（then, do, else, elif, if, while, until）の読み飛ばし
            m = re.match(
                r"^(?:then|do|else|elif|if|while|until)\b\s*", statement[offset:]
            )
            if m:
                offset += m.end()
                is_after_case_in = False
                continue
            # case ... in の読み飛ばし
            m = re.match(r"^case\b.*?\bin\b\s*", statement[offset:])
            if m:
                offset += m.end()
                is_after_case_in = True
                continue
            # case のパターン終端 ')' の読み飛ばし。例: '*) ' や 'a|b) '
            if is_after_case_in or not statement[offset:].strip().startswith("("):
                end_idx = ShellSourceMixin._find_case_pattern_end(statement[offset:])
                if end_idx is not None:
                    offset += end_idx
                    is_after_case_in = False
                    continue
            break

        # ループを抜けた後も、後続の判定のために先頭の空白をスキップ
        while offset < len(statement) and statement[offset].isspace():
            offset += 1

        statement_offset = offset
        statement = statement[statement_offset:]

        env_prefix = re.match(
            r"env\s+(?:(?:-i|--ignore-environment)\s+|(?:-u|--unset)\s+\S+\s+|--unset=\S+\s+)*",
            statement,
        )
        if env_prefix:
            env_end = statement_offset + env_prefix.end()
            while env_end < len(statement) and statement[env_end].isspace():
                env_end += 1
            return env_end

        declaration_prefix = re.match(
            r"(?:export|local|declare|typeset|readonly)(?:\s+(?:[-+][a-zA-Z0-9]+|--[a-zA-Z0-9-]+|--))*\s+",
            statement,
        )
        if declaration_prefix:
            dec_end = statement_offset + declaration_prefix.end()
            while dec_end < len(statement) and statement[dec_end].isspace():
                dec_end += 1
            return dec_end

        return statement_offset

    @staticmethod
    def _find_case_pattern_end(s: str) -> Optional[int]:
        # sの先頭から、caseパターンの終わりであるクォート外の ')' を探す。
        # (a|b) のように先頭に '(' がある場合もあるため、ネスト数を数える。
        # ただし、先頭に '(' がない場合は、最初の ')' で終了する。
        in_dquote = False
        in_squote = False
        escaped = False
        paren_depth = 0
        has_leading_paren = s.strip().startswith("(")

        # 先頭のスペースは読み飛ばす
        start_idx = 0
        while start_idx < len(s) and s[start_idx].isspace():
            start_idx += 1

        for idx in range(start_idx, len(s)):
            char = s[idx]
            if escaped:
                escaped = False
                continue
            if char == "\\" and not in_squote:
                escaped = True
                continue
            if in_dquote:
                if char == '"':
                    in_dquote = False
                continue
            if in_squote:
                if char == "'":
                    in_squote = False
                continue
            if char == '"':
                in_dquote = True
                continue
            if char == "'":
                in_squote = True
                continue
            if char == "(":
                paren_depth += 1
                continue
            if char == ")":
                if has_leading_paren:
                    paren_depth -= 1
                    if paren_depth == 0:
                        return idx + 1
                else:
                    if paren_depth == 0:
                        return idx + 1
                    paren_depth -= 1
        return None

    @staticmethod
    def _track_shell_case_allowlist_from_text(
        text: str, tainted_names: Set[str]
    ) -> None:
        """単一行 case allowlist が失敗時に終了する場合、その変数を安全化済みとして扱う。"""
        match = re.search(
            r"\bcase\s+\"?\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)(?:\})?\"?\s+in\b.*\*\)\s*(?:exit|return)\b.*\besac\b",
            text,
        )
        if match:
            tainted_names.discard(match.group(1))
