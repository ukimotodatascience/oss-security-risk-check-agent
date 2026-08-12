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

    @staticmethod
    def _register_shelljs_imports(text: str, sinks: Set[str]) -> None:
        import_equals_match = re.search(
            r"^\s*import\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['\"]shelljs['\"]\)",
            text,
        )
        if import_equals_match:
            sinks.add(f"{import_equals_match.group(1)}.exec")

        import_matches = re.finditer(
            r"^\s*import\s+((?:(?!\bimport\b).)*?)\s+from\s*['\"]shelljs['\"]",
            text,
        )
        for import_match in import_matches:
            import_clause = import_match.group(1).strip()
            namespace_match = re.search(
                r"(?:^|,)\s*\*\s*as\s+([A-Za-z_$][\w$]*)", import_clause
            )
            if namespace_match:
                sinks.add(f"{namespace_match.group(1)}.exec")
            default_binding = import_clause.split(",", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", default_binding):
                sinks.add(f"{default_binding}.exec")
            named_match = re.search(r"\{([^}]+)\}", import_clause)
            if named_match:
                for name in named_match.group(1).split(","):
                    name = name.strip()
                    default_alias_match = re.fullmatch(
                        r"default\s+as\s+([A-Za-z_$][\w$]*)", name
                    )
                    if default_alias_match:
                        sinks.add(f"{default_alias_match.group(1)}.exec")
                        continue
                    alias_match = re.match(r"exec\s+as\s+([A-Za-z_$][\w$]*)", name)
                    if name == "exec" or alias_match:
                        sinks.add(alias_match.group(1) if alias_match else name)

        module_match = re.search(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['\"]shelljs['\"]\)",
            text,
        )
        if module_match:
            sinks.add(f"{module_match.group(1)}.exec")

        require_match = re.search(
            r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\(['\"]shelljs['\"]\)",
            text,
        )
        if require_match:
            for name in require_match.group(1).split(","):
                name = name.strip()
                alias_match = re.match(r"exec\s*:\s*([A-Za-z_$][\w$]*)", name)
                if name == "exec" or alias_match:
                    sinks.add(alias_match.group(1) if alias_match else name)

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
