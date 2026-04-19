import ast
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from src.models import RiskRecord, Severity


class A2SqlInjectionRule:
    """SQL文字列連結や危険クエリ構築がないか"""

    rule_id = "A-2"
    category = "code"
    title = "SQL Injection"
    severity = Severity.MEDIUM

    _JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    _EXTERNAL_SOURCES = {
        "input",
        "os.getenv",
        "os.environ.get",
        "environ.get",
    }
    _SQL_EXECUTORS = {
        "execute",
        "executemany",
        "raw",
        "raw_query",
    }

    def _iter_py_files(self, target: Path) -> Iterable[Path]:
        for p in target.rglob("*.py"):
            if p.is_file():
                yield p

    def _iter_js_files(self, target: Path) -> Iterable[Path]:
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._JS_EXTS:
                yield p

    def _full_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._full_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None

    def _resolve_name(
        self, name: Optional[str], aliases: Dict[str, str]
    ) -> Optional[str]:
        if not name:
            return None
        if name in aliases:
            return aliases[name]
        head, dot, tail = name.partition(".")
        if head in aliases:
            mapped = aliases[head]
            return f"{mapped}.{tail}" if dot else mapped
        return name

    def _collect_aliases(self, tree: ast.AST) -> Dict[str, str]:
        aliases: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name] = item.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    if item.name == "*":
                        continue
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        return aliases

    def _is_external_expr(
        self, node: ast.AST, tainted: Set[str], aliases: Dict[str, str]
    ) -> bool:
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, ast.Attribute):
            full = self._resolve_name(self._full_name(node), aliases)
            return bool(full and full.startswith("request."))
        if isinstance(node, ast.Subscript):
            value_name = self._resolve_name(self._full_name(node.value), aliases)
            if value_name in {"sys.argv", "os.environ", "environ"}:
                return True
        if isinstance(node, ast.Call):
            callee = self._resolve_name(self._full_name(node.func), aliases)
            if callee in self._EXTERNAL_SOURCES:
                return True
            if callee and callee.startswith("request."):
                return True
        return any(
            self._is_external_expr(c, tainted, aliases)
            for c in ast.iter_child_nodes(node)
        )

    def _iter_assigned_names(self, target: ast.AST) -> Iterable[str]:
        if isinstance(target, ast.Name):
            yield target.id
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                yield from self._iter_assigned_names(e)

    def _is_sql_string_building(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return self._is_sql_string_building(
                    node.left
                ) or self._is_sql_string_building(node.right)
            if isinstance(node.op, ast.Mod):
                return isinstance(node.left, ast.Constant) and isinstance(
                    node.left.value, str
                )
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"format", "join"}:
                return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        return False

    def _is_parameterized_query(self, call: ast.Call, query_expr: ast.AST) -> bool:
        if len(call.args) >= 2:
            return True
        query = ""
        if isinstance(query_expr, ast.Constant) and isinstance(query_expr.value, str):
            query = query_expr.value
        if query and re.search(r"(%s|\?|:\w+)", query):
            return True
        return False

    def _collect_taint_and_sql_builders(
        self, tree: ast.AST, aliases: Dict[str, str]
    ) -> tuple[Set[str], Set[str]]:
        tainted: Set[str] = set()
        unsafe_sql_vars: Set[str] = set()

        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                if self._is_external_expr(node.value, tainted, aliases):
                    for t in node.targets:
                        for name in self._iter_assigned_names(t):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
                if self._is_sql_string_building(node.value) and self._is_external_expr(
                    node.value, tainted, aliases
                ):
                    for t in node.targets:
                        for name in self._iter_assigned_names(t):
                            if name not in unsafe_sql_vars:
                                unsafe_sql_vars.add(name)
                                changed = True
        return tainted, unsafe_sql_vars

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for py_file in self._iter_py_files(target):
            try:
                src = py_file.read_text(encoding="utf-8")
                tree = ast.parse(src)
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            aliases = self._collect_aliases(tree)
            tainted, unsafe_sql_vars = self._collect_taint_and_sql_builders(
                tree, aliases
            )
            rel_path = str(py_file.relative_to(target))

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                callee = self._resolve_name(self._full_name(node.func), aliases)
                if not callee:
                    continue

                func_name = callee.rsplit(".", 1)[-1]
                if func_name not in self._SQL_EXECUTORS:
                    continue
                if not node.args:
                    continue

                query_expr = node.args[0]
                has_external = self._is_external_expr(query_expr, tainted, aliases)
                if (
                    isinstance(query_expr, ast.Name)
                    and query_expr.id in unsafe_sql_vars
                ):
                    has_external = True
                is_dynamic = self._is_sql_string_building(query_expr)
                param_safe = self._is_parameterized_query(node, query_expr)

                if has_external and is_dynamic and not param_safe:
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=getattr(node, "lineno", None),
                            message="外部入力を連結・整形したSQLを実行しています（パラメータ化不足）",
                        )
                    )
                elif has_external and not param_safe:
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=getattr(node, "lineno", None),
                            message="外部入力を含むSQL実行です。バインド変数を利用してください",
                        )
                    )

        js_sink = re.compile(r"\b(?:query|execute)\s*\((?P<arg>.+)\)")
        js_external = re.compile(
            r"req\.(?:query|body|params)|request\.(?:query|body|params)|process\.argv"
        )
        for js_file in self._iter_js_files(target):
            try:
                lines = js_file.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            rel_path = str(js_file.relative_to(target))
            for i, line in enumerate(lines, start=1):
                m = js_sink.search(line)
                if not m:
                    continue
                arg = m.group("arg")
                dynamic = "${" in arg or "+" in arg or ".concat(" in arg
                if js_external.search(arg):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH if dynamic else Severity.MEDIUM,
                            file_path=rel_path,
                            line=i,
                            message="外部入力を含むSQL実行が確認されました",
                        )
                    )

        return records
