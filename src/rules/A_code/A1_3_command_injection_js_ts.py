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
    ts_child_by_field_name,
    ts_node_text,
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
            line = getattr(node, "start_point", (0, 0))[0] + 1
            has_external = self._js_has_external_input(call_text, tainted_names)
            if not has_external:
                continue
            callee_tail = callee.split(".")[-1]
            is_known_sink = (
                callee in child_process_sinks or callee_tail in child_process_sinks
            )
            if not is_known_sink and (not child_process_sinks):
                is_known_sink = callee_tail in self._CHILD_PROCESS_NAMES
            if not is_known_sink:
                continue
            if callee_tail in {"exec", "execSync"}:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=line,
                        message="External input reaches child_process command execution",
                    )
                )
                continue
            if callee_tail in {"execFile", "execFileSync", "fork"}:
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line=line,
                        message="External input reaches child_process file execution",
                    )
                )
                continue
            if callee_tail in {"spawn", "spawnSync"}:
                has_shell_true = "shell: true" in call_text or "shell:true" in call_text
                records.append(
                    RiskRecord(
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
                )
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
        child_process_sinks: Set[str] = set()
        shell_true_option_names: Set[str] = set()
        lines = src.splitlines()
        statements: List[Tuple[int, str]] = []
        buffer = ""
        start_line = 1
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            if not buffer:
                start_line = i
            buffer = f"{buffer} {stripped}".strip()
            if stripped.endswith((";", "}", ")")):
                statements.append((start_line, buffer))
                buffer = ""
        if buffer:
            statements.append((start_line, buffer))
        for i, stripped in statements:
            self._register_child_process_imports(stripped, child_process_sinks)
            m = re.search(
                "\\b(?:const|let|var)\\s+([A-Za-z_$][\\w$]*)\\s*=\\s*(.+)$", stripped
            )
            if m:
                (var_name, rhs) = (m.group(1), m.group(2))
                rhs_clean = rhs.rstrip(";").strip()
                if self._is_child_process_alias_assignment(
                    rhs_clean, child_process_sinks
                ):
                    child_process_sinks.add(var_name)
                if self._js_options_enable_shell(rhs_clean):
                    shell_true_option_names.add(var_name)
                if self._js_has_external_input(rhs, tainted_names):
                    tainted_names.add(var_name)
            if re.search("\\b(?:execFile|execFileSync|fork)\\s*\\(", stripped):
                if self._js_has_external_input(stripped, tainted_names):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=i,
                            message="External input reaches child_process file execution",
                        )
                    )
                continue
            if self._is_known_third_party_shell_sink(stripped):
                if self._js_has_external_input(stripped, tainted_names):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=i,
                            message="External input reaches shell command execution helper",
                        )
                    )
                continue
            exec_names = child_process_sinks or {"exec", "execSync"}
            if any(
                (
                    re.search(f"(?<![\\w$]){re.escape(name)}\\s*\\(", stripped)
                    for name in exec_names
                    if name.split(".")[-1] in {"exec", "execSync"}
                    or name in {"exec", "execSync"}
                    or "." not in name
                )
            ):
                if self._js_has_external_input(stripped, tainted_names):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=i,
                            message="External input reaches child_process command execution",
                        )
                    )
                continue
            spawn_names = child_process_sinks or {"spawn", "spawnSync"}
            if any(
                (
                    re.search(f"(?<![\\w$]){re.escape(name)}\\s*\\(", stripped)
                    for name in spawn_names
                    if name.split(".")[-1] in {"spawn", "spawnSync"}
                    or name in {"spawn", "spawnSync"}
                    or "." not in name
                )
            ):
                if not self._js_has_external_input(stripped, tainted_names):
                    continue
                has_shell_true = self._js_call_enables_shell(
                    stripped, shell_true_option_names
                )
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH if has_shell_true else Severity.MEDIUM,
                        file_path=rel_path,
                        line=i,
                        message="External input reaches child_process spawn with shell=true"
                        if has_shell_true
                        else "External input reaches child_process spawn",
                    )
                )
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

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for js_file in self._iter_js_ts_files(target):
            records.extend(self._evaluate_js_ts_file(js_file, target))
        return dedupe_records(records)
