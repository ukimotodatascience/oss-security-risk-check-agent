import re
from typing import Set


CHILD_PROCESS_NAMES = {
    "exec",
    "execSync",
    "spawn",
    "spawnSync",
    "execFile",
    "execFileSync",
    "fork",
}


class JsTsSinkMixin:
    _CHILD_PROCESS_NAMES = CHILD_PROCESS_NAMES

    def _register_child_process_imports(self, text: str, sinks: Set[str]) -> None:
        import_match = re.search(
            r"import\s*\{([^}]+)\}\s*from\s*['\"](?:node:)?child_process['\"]",
            text,
        )
        if import_match:
            for name in import_match.group(1).split(","):
                name = name.strip()
                alias_match = re.match(
                    r"(execFileSync|execFile|execSync|exec|spawnSync|spawn|fork)\s+as\s+([A-Za-z_$][\w$]*)",
                    name,
                )
                sinks.add(alias_match.group(2) if alias_match else name)

        require_match = re.search(
            r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['\"](?:node:)?child_process['\"]\)",
            text,
        )
        if require_match:
            for name in require_match.group(1).split(","):
                name = name.strip()
                alias_match = re.match(
                    r"(execFileSync|execFile|execSync|exec|spawnSync|spawn|fork)\s*:\s*([A-Za-z_$][\w$]*)",
                    name,
                )
                sinks.add(alias_match.group(2) if alias_match else name)

        module_match = re.search(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['\"](?:node:)?child_process['\"]\)",
            text,
        )
        if module_match:
            module_name = module_match.group(1)
            sinks.add(module_name)
            sinks.update(f"{module_name}.{name}" for name in self._CHILD_PROCESS_NAMES)

    def _is_child_process_alias_assignment(
        self, rhs_clean: str, sinks: Set[str]
    ) -> bool:
        return (
            rhs_clean in sinks
            or rhs_clean.split(".")[-1] in sinks
            or any(
                rhs_clean == f"{sink}.{name}"
                for sink in sinks
                for name in self._CHILD_PROCESS_NAMES
            )
        )
