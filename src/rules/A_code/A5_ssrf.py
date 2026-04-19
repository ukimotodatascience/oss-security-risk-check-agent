import ast
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from src.models import RiskRecord, Severity


class A5SsrfRule:
    """外部入力でURLアクセス先を制御可能になっていないか"""

    rule_id = "A-5"
    category = "code"
    title = "SSRF"
    severity = Severity.MEDIUM

    _EXTERNAL_SOURCES = {
        "input",
        "os.getenv",
        "os.environ.get",
        "environ.get",
    }
    _HTTP_SINKS = {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.request",
        "urllib.request.urlopen",
        "urllib3.PoolManager.request",
    }

    def _iter_py_files(self, target: Path) -> Iterable[Path]:
        for p in target.rglob("*.py"):
            if p.is_file():
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

    def _iter_assigned_names(self, target: ast.AST) -> Iterable[str]:
        if isinstance(target, ast.Name):
            yield target.id
        elif isinstance(target, (ast.List, ast.Tuple)):
            for e in target.elts:
                yield from self._iter_assigned_names(e)

    def _is_external_expr(
        self, node: ast.AST, tainted: Set[str], aliases: Dict[str, str]
    ) -> bool:
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, ast.Attribute):
            full = self._resolve_name(self._full_name(node), aliases)
            return bool(full and full.startswith("request."))
        if isinstance(node, ast.Subscript):
            base = self._resolve_name(self._full_name(node.value), aliases)
            if base in {"sys.argv", "os.environ", "environ"}:
                return True
        if isinstance(node, ast.Call):
            callee = self._resolve_name(self._full_name(node.func), aliases)
            if callee in self._EXTERNAL_SOURCES:
                return True
            if callee and callee.startswith("request."):
                return True

        for child in ast.iter_child_nodes(node):
            if self._is_external_expr(child, tainted, aliases):
                return True
        return False

    def _collect_tainted(self, tree: ast.AST, aliases: Dict[str, str]) -> Set[str]:
        tainted: Set[str] = set()
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    if self._is_external_expr(node.value, tainted, aliases):
                        for t in node.targets:
                            for name in self._iter_assigned_names(t):
                                if name not in tainted:
                                    tainted.add(name)
                                    changed = True
                elif isinstance(node, ast.AnnAssign) and node.value:
                    if self._is_external_expr(node.value, tainted, aliases):
                        for name in self._iter_assigned_names(node.target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
        return tainted

    def evaluate(self, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []

        for py_file in self._iter_py_files(target):
            try:
                src = py_file.read_text(encoding="utf-8")
                tree = ast.parse(src)
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            aliases = self._collect_aliases(tree)
            tainted = self._collect_tainted(tree, aliases)
            rel_path = str(py_file.relative_to(target))

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                callee = self._resolve_name(self._full_name(node.func), aliases)
                if callee not in self._HTTP_SINKS:
                    continue

                url_arg = node.args[0] if node.args else None
                for kw in node.keywords:
                    if kw.arg in {"url", "uri"}:
                        url_arg = kw.value
                        break
                if url_arg is None:
                    continue

                if self._is_external_expr(url_arg, tainted, aliases):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=getattr(node, "lineno", None),
                            message="外部入力でHTTPアクセス先URLを制御しています（SSRFの恐れ）",
                        )
                    )

        return records
