import ast
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from src.models import RiskRecord, Severity


class A3UnsafeDeserializationRule:
    """危険なデシリアライズがないか"""

    rule_id = "A-3"
    category = "code"
    title = "Unsafe Deserialization"
    severity = Severity.MEDIUM

    _EXTERNAL_SOURCES = {
        "input",
        "os.getenv",
        "os.environ.get",
        "environ.get",
    }
    _DANGEROUS_CALLS = {
        "pickle.loads",
        "pickle.load",
        "dill.loads",
        "dill.load",
        "marshal.loads",
        "jsonpickle.decode",
        "yaml.load",
    }
    _SAFE_CALLS = {
        "yaml.safe_load",
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

        for child in ast.iter_child_nodes(node):
            if self._is_external_expr(child, tainted, aliases):
                return True
        return False

    def _iter_assigned_names(self, target: ast.AST) -> Iterable[str]:
        if isinstance(target, ast.Name):
            yield target.id
        elif isinstance(target, (ast.List, ast.Tuple)):
            for e in target.elts:
                yield from self._iter_assigned_names(e)

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

    def _yaml_loader_is_safe(self, call: ast.Call, aliases: Dict[str, str]) -> bool:
        for kw in call.keywords:
            if kw.arg != "Loader":
                continue
            loader_name = self._resolve_name(self._full_name(kw.value), aliases)
            if loader_name and loader_name.endswith("SafeLoader"):
                return True
        return False

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
                if not callee or callee in self._SAFE_CALLS:
                    continue
                if callee not in self._DANGEROUS_CALLS:
                    continue
                if callee == "yaml.load" and self._yaml_loader_is_safe(node, aliases):
                    continue

                arg0 = node.args[0] if node.args else None
                has_external = bool(
                    arg0 and self._is_external_expr(arg0, tainted, aliases)
                )

                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH if has_external else Severity.MEDIUM,
                        file_path=rel_path,
                        line=getattr(node, "lineno", None),
                        message=(
                            "信頼できない入力を危険なデシリアライズAPIで処理しています"
                            if has_external
                            else "危険なデシリアライズAPIを使用しています。入力ソースの信頼性確認が必要です"
                        ),
                    )
                )

        return records
