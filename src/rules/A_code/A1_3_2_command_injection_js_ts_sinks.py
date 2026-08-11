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
        import_matches = re.finditer(
            r"import\s+(.*?)\s+from\s+['\"](?:node:)?child_process['\"]",
            text,
        )
        for import_match in import_matches:
            imports_str = import_match.group(1).strip()

            # 1. Extract namespace import if present (e.g. * as ns)
            ns_match = re.search(r"\*\s*as\s+([A-Za-z_$][\w$]*)", imports_str)
            if ns_match:
                ns_name = ns_match.group(1)
                if is_dict:
                    sinks[ns_name] = "child_process"
                    for name in self._CHILD_PROCESS_NAMES:
                        sinks[f"{ns_name}.{name}"] = name
                else:
                    sinks.add(ns_name)
                    sinks.update(
                        f"{ns_name}.{name}" for name in self._CHILD_PROCESS_NAMES
                    )
                # Remove the namespace part from imports_str
                imports_str = imports_str.replace(ns_match.group(0), "")

            # 2. Extract named imports if present (e.g. { exec, spawn })
            named_match = re.search(r"\{([^}]+)\}", imports_str)
            if named_match:
                for name in named_match.group(1).split(","):
                    name = name.strip()
                    if not name:
                        continue
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
                # Remove the named part from imports_str
                imports_str = re.sub(r"\{[^}]*\}", "", imports_str)

            # 3. Any remaining part is the default import
            default_part = imports_str.strip(", \n\t")
            if default_part:
                def_name = default_part.split(",")[0].strip()
                if def_name:
                    if is_dict:
                        sinks[def_name] = "child_process"
                        for name in self._CHILD_PROCESS_NAMES:
                            sinks[f"{def_name}.{name}"] = name
                    else:
                        sinks.add(def_name)
                        sinks.update(
                            f"{def_name}.{name}" for name in self._CHILD_PROCESS_NAMES
                        )

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

        module_matches = re.finditer(
            r"(?<![\w$.])(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*require\(['\"](?:node:)?child_process['\"]\)(?:\.([A-Za-z_$][\w$]*))?",
            text,
        )
        for module_match in module_matches:
            module_name = module_match.group(1)
            prop_name = module_match.group(2)
            if prop_name:
                if is_dict:
                    sinks[module_name] = prop_name
                else:
                    sinks.add(module_name)
            else:
                if is_dict:
                    sinks[module_name] = "child_process"
                    for name in self._CHILD_PROCESS_NAMES:
                        sinks[f"{module_name}.{name}"] = name
                else:
                    sinks.add(module_name)
                    sinks.update(
                        f"{module_name}.{name}" for name in self._CHILD_PROCESS_NAMES
                    )

        dynamic_import_matches = re.finditer(
            r"(?<![\w$.])(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?import\(['\"](?:node:)?child_process['\"]\)",
            text,
        )
        for dynamic_import_match in dynamic_import_matches:
            module_name = dynamic_import_match.group(1)
            if is_dict:
                sinks[module_name] = "child_process"
                for name in self._CHILD_PROCESS_NAMES:
                    sinks[f"{module_name}.{name}"] = name
            else:
                sinks.add(module_name)
                sinks.update(
                    f"{module_name}.{name}" for name in self._CHILD_PROCESS_NAMES
                )

        dynamic_destruct_matches = re.finditer(
            r"(?<![\w$.])(?:(?:const|let|var)\s*)?\{([^}]+)\}\s*=\s*(?:await\s+)?import\(['\"](?:node:)?child_process['\"]\)",
            text,
        )
        for dynamic_destruct_match in dynamic_destruct_matches:
            for name in dynamic_destruct_match.group(1).split(","):
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

    def _get_child_process_original_name(
        self, rhs_clean: str, sinks: Union[Set[str], Dict[str, str]]
    ) -> Optional[str]:
        if re.fullmatch(r"require\(['\"](?:node:)?child_process['\"]\)", rhs_clean):
            return "child_process"
        if not isinstance(sinks, dict):
            # sinks が set の場合は、単にメンバシップをチェックして自身を返す（フォールバック）
            if rhs_clean in sinks:
                return rhs_clean
            for sink in sinks:
                for name in self._CHILD_PROCESS_NAMES:
                    if rhs_clean == f"{sink}.{name}":
                        return name
            rhs_tail = rhs_clean.split(".")[-1]
            if rhs_tail in sinks:
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
        return None

    def _is_child_process_alias_assignment(
        self, rhs_clean: str, sinks: Union[Set[str], Dict[str, str]]
    ) -> bool:
        return self._get_child_process_original_name(rhs_clean, sinks) is not None
