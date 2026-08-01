import re
from pathlib import Path
from typing import Iterable, List, Optional, Set
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
)
from src.rules.A_code.A1_4_1_command_injection_shell_sources import ShellSourceMixin


class ShellCommandInjectionDetector(ShellSourceMixin):
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
        lines = src.splitlines()
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            stmt_start_idx = line.find(stripped)
            if stmt_start_idx == -1:
                stmt_start_idx = len(line) - len(line.lstrip())

            self._track_shell_taint_from_text(stripped, tainted_names)
            self._track_shell_case_allowlist_from_text(stripped, tainted_names)
            has_external = self._shell_expands_external_input(stripped, tainted_names)
            if not has_external:
                continue

            # 1. eval
            for m in re.finditer("\\beval\\b", stripped):
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

            # 2. sh, bash, zsh, ksh -c
            for m in re.finditer("\\b(?:sh|bash|zsh|ksh)\\s+-c\\b", stripped):
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message="External input reaches shell -c execution",
                )
                col = stmt_start_idx + m.start()
                rec._column = col
                rec._char_offset = line_col_to_offset(src, i, col)
                records.append(rec)

            # 3. backtick command substitution
            for m in re.finditer("`[^`]*\\$[^`]*`", stripped):
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

            # 6. xargs/find -c
            for m in re.finditer(
                "\\b(?:xargs|find)\\b.*\\b(?:sh|bash|zsh|ksh)\\s+-c\\b", stripped
            ):
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=i,
                    message="External input reaches xargs/find shell -c execution",
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
            text = ts_node_text(src_bytes, node).strip()
            if not text or text.startswith("#"):
                continue
            start_point = getattr(node, "start_point", (0, 0))
            line = start_point[0] + 1
            col = start_point[1]
            self._track_shell_taint_from_text(text, tainted_names)
            self._track_shell_case_allowlist_from_text(text, tainted_names)
            if not self._shell_expands_external_input(text, tainted_names):
                continue
            byte_offset = getattr(node, "start_byte", 0)
            if re.search("\\beval\\b", text):
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=line,
                    message="External input reaches shell eval",
                )
                rec._column = col
                rec._char_offset = len(
                    src_bytes[:byte_offset].decode("utf-8", errors="replace")
                )
                records.append(rec)
                continue
            if re.search("\\b(?:sh|bash|zsh|ksh)\\s+-c\\b", text):
                rec = RiskRecord(
                    rule_id=self.rule_id,
                    category=self.category,
                    title=self.title,
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line=line,
                    message="External input reaches shell -c execution",
                )
                rec._column = col
                rec._char_offset = len(
                    src_bytes[:byte_offset].decode("utf-8", errors="replace")
                )
                records.append(rec)
                continue
            is_cmd_sub = getattr(node, "type", "") == "command_substitution"
            if is_cmd_sub or re.search("\\$\\([^)]*\\$[^)]*\\)", text):
                is_backtick = False
                if is_cmd_sub:
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

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        for shell_file in self._iter_shell_files(target):
            records.extend(self._evaluate_shell_file(shell_file, target))
        return dedupe_records(records)
