import re
from typing import Set


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
            r"([A-Za-z_][A-Za-z0-9_]*)=([^\s'\"`]+|'[^']*'|\"[^\"]*\"|`[^`]*`|\$\([^)]*\))(?:\s+|;\s*|$)"
        )
        for statement in self._split_shell_statements(text):
            statement = statement.strip()
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
        while True:
            # { の読み飛ばし
            m = re.match(r"^(?:\{\s*)+", statement[offset:])
            if m:
                offset += m.end()
                continue
            # then や do の読み飛ばし
            m = re.match(r"^(?:then|do)\b\s*", statement[offset:])
            if m:
                offset += m.end()
                continue
            # case ... in の読み飛ばし
            m = re.match(r"^case\b.*?\bin\b\s*", statement[offset:])
            if m:
                offset += m.end()
                continue
            # case のパターン終端 ')' の読み飛ばし。例: '*) ' や 'a) '
            m = re.match(r"^(?:[A-Za-z0-9_*?-]+)\)\s*", statement[offset:])
            if m:
                offset += m.end()
                continue
            break

        statement_offset = offset
        statement = statement[statement_offset:]

        env_prefix = re.match(
            r"env\s+(?:(?:-i|--ignore-environment)\s+|(?:-u|--unset)\s+\S+\s+|--unset=\S+\s+)*",
            statement,
        )
        if env_prefix:
            return statement_offset + env_prefix.end()
        declaration_prefix = re.match(
            r"(?:export|local|declare|typeset|readonly)(?:\s+(?:-[a-zA-Z0-9]+|--[a-zA-Z0-9-]+|--))*\s+",
            statement,
        )
        return (
            statement_offset + declaration_prefix.end()
            if declaration_prefix
            else statement_offset
        )

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
