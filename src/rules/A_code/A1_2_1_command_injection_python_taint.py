import ast
from typing import Dict, Iterable, Optional, Set


class PythonTaintMixin:
    _EXTERNAL_SOURCE_CALLS = {"input", "os.getenv", "os.environ.get", "environ.get"}

    @staticmethod
    def _is_request_like_name(name: Optional[str]) -> bool:
        """Flask/Django/FastAPI などでよく使われる request オブジェクト名を判定する。"""
        if not name:
            return False
        return (
            name == "request"
            or name.startswith("request.")
            or name == "flask.request"
            or name.startswith("flask.request.")
        )

    def _full_name(self, node: ast.AST) -> Optional[str]:
        """AST ノードから呼び出し名/属性名をドット区切りで復元する。"""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._full_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None

    @staticmethod
    def _resolve_name(name: Optional[str], aliases: Dict[str, str]) -> Optional[str]:
        """import alias を実体名に解決する。"""
        if not name:
            return None

        if name in aliases:
            return aliases[name]

        head, dot, tail = name.partition(".")
        if head in aliases:
            mapped = aliases[head]
            if dot:
                return f"{mapped}.{tail}"
            return mapped
        return name

    @staticmethod
    def _collect_import_aliases(tree: ast.AST) -> Dict[str, str]:
        """import / from import の別名対応表を作る。"""
        aliases: Dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    local = item.asname or item.name
                    aliases[local] = item.name
            elif isinstance(node, ast.ImportFrom):
                if not node.module:
                    continue
                for item in node.names:
                    if item.name == "*":
                        continue
                    local = item.asname or item.name
                    aliases[local] = f"{node.module}.{item.name}"
        return aliases

    def _expr_key(self, node: ast.AST) -> Optional[str]:
        """Name / Attribute / 単純な Subscript を taint 追跡用キーに変換する。"""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._expr_key(node.value)
            if base:
                return f"{base}.{node.attr}"
        if isinstance(node, ast.Subscript):
            base = self._expr_key(node.value)
            if not base:
                return None
            slice_node = node.slice
            if isinstance(slice_node, ast.Constant):
                return f"{base}[{slice_node.value!r}]"
            return f"{base}[]"
        return None

    def _is_external_input_expr(
        self,
        node: ast.AST,
        tainted_names: Set[str],
        aliases: Dict[str, str],
        taint_returning_functions: Optional[Set[str]] = None,
    ) -> bool:
        """式が外部入力由来（または tainted 変数由来）かを再帰的に判定する。"""
        taint_returning_functions = taint_returning_functions or set()

        expr_key = self._expr_key(node)
        if expr_key and expr_key in tainted_names:
            return True

        if isinstance(node, ast.Subscript):
            base_key = self._expr_key(node.value)
            if base_key and base_key in tainted_names:
                return True

            target_name = self._resolve_name(self._full_name(node.value), aliases)
            if target_name in {"sys.argv", "os.environ", "environ"}:
                return True

        if isinstance(node, ast.Attribute):
            full = self._resolve_name(self._full_name(node), aliases)
            return self._is_request_like_name(full)

        if isinstance(node, ast.Call):
            callee = self._resolve_name(self._full_name(node.func), aliases)
            if callee in self._EXTERNAL_SOURCE_CALLS:
                return True
            if self._is_request_like_name(callee):
                return True
            if callee and callee.endswith(".parse_args"):
                return True
            if callee in taint_returning_functions and any(
                self._is_external_input_expr(
                    arg, tainted_names, aliases, taint_returning_functions
                )
                for arg in node.args
            ):
                return True

        for child in ast.iter_child_nodes(node):
            if self._is_external_input_expr(
                child, tainted_names, aliases, taint_returning_functions
            ):
                return True

        return False

    @staticmethod
    def _iter_assigned_names(target: ast.AST) -> Iterable[str]:
        helper = PythonTaintMixin()
        if isinstance(target, ast.Name):
            yield target.id
            return
        if isinstance(target, ast.Attribute):
            key = helper._expr_key(target)
            if key:
                yield key
            return
        if isinstance(target, ast.Subscript):
            key = helper._expr_key(target)
            if key:
                yield key
            base_key = helper._expr_key(target.value)
            if base_key:
                yield base_key
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                yield from PythonTaintMixin._iter_assigned_names(elt)

    def _collect_tainted_names(
        self,
        tree: ast.AST,
        aliases: Dict[str, str],
        taint_returning_functions: Optional[Set[str]] = None,
    ) -> Set[str]:
        """代入解析を繰り返し、外部入力由来の変数名集合を収集する。"""
        tainted: Set[str] = set()

        changed = True
        while changed:
            changed = False
            for node in self._walk_scope_nodes(tree):
                if isinstance(node, ast.Assign):
                    if self._is_external_input_expr(
                        node.value, tainted, aliases, taint_returning_functions
                    ):
                        for target in node.targets:
                            for name in self._iter_assigned_names(target):
                                if name not in tainted:
                                    tainted.add(name)
                                    changed = True
                    continue

                if isinstance(node, ast.AnnAssign):
                    if node.value and self._is_external_input_expr(
                        node.value, tainted, aliases, taint_returning_functions
                    ):
                        for name in self._iter_assigned_names(node.target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
                    continue

                if isinstance(node, ast.AugAssign):
                    if self._is_external_input_expr(
                        node.value, tainted, aliases, taint_returning_functions
                    ):
                        for name in self._iter_assigned_names(node.target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
                    continue

                if isinstance(node, ast.For):
                    if self._is_external_input_expr(
                        node.iter, tainted, aliases, taint_returning_functions
                    ):
                        for name in self._iter_assigned_names(node.target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
        return tainted

    @staticmethod
    def _walk_scope_nodes(tree: ast.AST) -> Iterable[ast.AST]:
        """指定スコープ内のノードを、ネストした関数/メソッド本体を除外して列挙する。"""
        yield tree
        stack = list(reversed(list(ast.iter_child_nodes(tree))))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            yield node
            stack.extend(reversed(list(ast.iter_child_nodes(node))))

    @staticmethod
    def _iter_analysis_scopes(tree: ast.AST) -> Iterable[ast.AST]:
        """taint のスコープ混線を抑えるため、モジュールと各関数を解析単位として返す。"""
        yield tree
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node

    def _collect_taint_returning_functions(
        self, tree: ast.AST, aliases: Dict[str, str]
    ) -> Set[str]:
        """引数由来の値を返す関数を、簡易的な関数間 taint 伝播関数として収集する。"""
        function_defs = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        functions: Set[str] = set()

        changed = True
        while changed:
            changed = False
            for node in function_defs:
                if node.name in functions:
                    continue
                params = {arg.arg for arg in node.args.args}
                if not params:
                    continue

                tainted = set(params)
                tainted.update(self._collect_tainted_names(node, aliases, functions))
                for child in self._walk_scope_nodes(node):
                    if not isinstance(child, ast.Return) or child.value is None:
                        continue
                    if self._is_external_input_expr(
                        child.value, tainted, aliases, functions
                    ):
                        functions.add(node.name)
                        changed = True
                        break
        return functions

    def _describe_taint_sources(
        self,
        node: ast.AST,
        tainted_names: Set[str],
        aliases: Dict[str, str],
        taint_returning_functions: Set[str],
    ) -> str:
        """RiskRecord の message に付与する簡易 taint 経路情報を作る。"""
        sources: Set[str] = set()

        for child in ast.walk(node):
            key = self._expr_key(child)
            if key and key in tainted_names:
                sources.add(key)
            if isinstance(child, ast.Subscript):
                target_name = self._resolve_name(self._full_name(child.value), aliases)
                if target_name in {"sys.argv", "os.environ", "environ"}:
                    sources.add(target_name)
            if isinstance(child, ast.Attribute):
                full = self._resolve_name(self._full_name(child), aliases)
                if full and self._is_request_like_name(full):
                    sources.add(full)
            if isinstance(child, ast.Call):
                callee = self._resolve_name(self._full_name(child.func), aliases)
                if callee in self._EXTERNAL_SOURCE_CALLS:
                    sources.add(callee)
                elif callee and self._is_request_like_name(callee):
                    sources.add(callee)
                elif callee and callee.endswith(".parse_args"):
                    sources.add(callee)
                elif callee in taint_returning_functions:
                    sources.add(f"{callee}(...) return")

        if not sources:
            return ""
        return f" / taint: {', '.join(sorted(sources))}"

    @staticmethod
    def _static_full_name(node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = PythonTaintMixin._static_full_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None
