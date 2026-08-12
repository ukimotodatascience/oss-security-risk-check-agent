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
