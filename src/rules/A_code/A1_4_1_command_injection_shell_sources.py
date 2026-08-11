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
            is_separator = char == ";" or text[idx : idx + 2] in {"&&", "||"}
            if is_separator:
                statements.append(text[start:idx])
                start = idx + (2 if text[idx : idx + 2] in {"&&", "||"} else 1)
        statements.append(text[start:])
        return statements

    @staticmethod
    def _shell_assignment_start_position(statement: str) -> int:
        group_prefix = re.match(r"(?:\{\s*)+", statement)
        if group_prefix:
            statement_offset = group_prefix.end()
            statement = statement[statement_offset:]
        else:
            statement_offset = 0
        env_prefix = re.match(
            r"env\s+(?:(?:-i|--ignore-environment)\s+|(?:-u|--unset)\s+\S+\s+|--unset=\S+\s+)*",
            statement,
        )
        if env_prefix:
            return statement_offset + env_prefix.end()
        declaration_prefix = re.match(
            r"(?:export|local|declare|typeset|readonly)\s+", statement
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
