import re
from typing import Dict, Union, Set, Optional

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

    def _register_child_process_imports(
        self, text: str, sinks: Union[Set[str], Dict[str, str]]
    ) -> None:
        is_dict = isinstance(sinks, dict)
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
                if alias_match:
                    if is_dict:
                        sinks[alias_match.group(2)] = alias_match.group(1)
                    else:
                        sinks.add(alias_match.group(2))
                else:
                    if is_dict:
                        sinks[name] = name
                    else:
                        sinks.add(name)

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
                if alias_match:
                    if is_dict:
                        sinks[alias_match.group(2)] = alias_match.group(1)
                    else:
                        sinks.add(alias_match.group(2))
                else:
                    if is_dict:
                        sinks[name] = name
                    else:
                        sinks.add(name)

        ns_import_match = re.search(
            r"import\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\s*['\"](?:node:)?child_process['\"]",
            text,
        )
        if ns_import_match:
            ns_name = ns_import_match.group(1)
            if is_dict:
                sinks[ns_name] = "child_process"
                for name in self._CHILD_PROCESS_NAMES:
                    sinks[f"{ns_name}.{name}"] = name
            else:
                sinks.add(ns_name)
                sinks.update(f"{ns_name}.{name}" for name in self._CHILD_PROCESS_NAMES)

        module_match = re.search(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(['\"](?:node:)?child_process['\"]\)",
            text,
        )
        if module_match:
            module_name = module_match.group(1)
            if is_dict:
                sinks[module_name] = "child_process"
                for name in self._CHILD_PROCESS_NAMES:
                    sinks[f"{module_name}.{name}"] = name
            else:
                sinks.add(module_name)
                sinks.update(
                    f"{module_name}.{name}" for name in self._CHILD_PROCESS_NAMES
                )

    def _get_child_process_original_name(
        self, rhs_clean: str, sinks: Union[Set[str], Dict[str, str]]
    ) -> Optional[str]:
        if not isinstance(sinks, dict):
            # sinks が set の場合は、単にメンバシップをチェックして自身を返す（フォールバック）
            if rhs_clean in sinks:
                return rhs_clean
            for sink in sinks:
                for name in self._CHILD_PROCESS_NAMES:
                    if rhs_clean == f"{sink}.{name}":
                        return name
            rhs_tail = rhs_clean.split(".")[-1]
            if rhs_tail in sinks or rhs_tail in self._CHILD_PROCESS_NAMES:
                return rhs_tail
            return None

        if rhs_clean in sinks:
            return sinks[rhs_clean]
        for sink, original in sinks.items():
            if original == "child_process":
                for name in self._CHILD_PROCESS_NAMES:
                    if rhs_clean == f"{sink}.{name}":
                        return name
        if "." in rhs_clean:
            rhs_tail = rhs_clean.split(".")[-1]
            if rhs_tail in sinks:
                return sinks[rhs_tail]
            if rhs_tail in self._CHILD_PROCESS_NAMES:
                return rhs_tail
        return None

    def _is_child_process_alias_assignment(
        self, rhs_clean: str, sinks: Union[Set[str], Dict[str, str]]
    ) -> bool:
        return self._get_child_process_original_name(rhs_clean, sinks) is not None
