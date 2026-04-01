import ast
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from src.models import RiskRecord, Severity


class A1CommandInjectionRule:
    """外部入力がOSコマンド実行に流れていないか"""

    rule_id = "A-1"
    category = "code"
    title = "Command Injection"
    severity = Severity.MEDIUM

    _DANGEROUS_CALLS = {
        "os.system",
        "os.popen",
        "os.spawnl",
        "os.spawnlp",
        "os.spawnv",
        "os.spawnvp",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "asyncio.create_subprocess_shell",
    }

    _SHELL_LIKE_CALLS = {
        "os.system",
        "os.popen",
        "asyncio.create_subprocess_shell",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }

    _EXTERNAL_SOURCE_CALLS = {
        "input",
        "os.getenv",
        "os.environ.get",
        "environ.get",
    }

    _SUBPROCESS_CMD_KWARGS = {"args", "cmd", "command"}

    _JS_TS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
    _SHELL_EXTENSIONS = {".sh", ".bash", ".zsh", ".ksh"}

    _JS_EXTERNAL_SOURCE_TOKENS = {
        "req.query",
        "req.body",
        "req.params",
        "req.headers",
        "request.query",
        "request.body",
        "request.params",
        "request.headers",
        "ctx.query",
        "ctx.request.body",
        "process.argv",
        "process.env",
    }

    def _iter_python_files(self, target: Path) -> Iterable[Path]:
        """対象ディレクトリ配下の Python ファイルを再帰的に列挙する。"""
        for p in target.rglob("*.py"):
            if p.is_file():
                yield p

    def _iter_js_ts_files(self, target: Path) -> Iterable[Path]:
        """対象ディレクトリ配下の JavaScript / TypeScript ファイルを列挙する。"""
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._JS_TS_EXTENSIONS:
                yield p

    def _iter_shell_files(self, target: Path) -> Iterable[Path]:
        """対象ディレクトリ配下の shell script を列挙する。"""
        for p in target.rglob("*"):
            if p.is_file() and p.suffix.lower() in self._SHELL_EXTENSIONS:
                yield p

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

    def _is_string_building_expr(self, node: ast.AST) -> bool:
        """文字列連結・f文字列・format など、コマンド文字列構築を示す式か判定する。"""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Add):
                return self._is_string_building_expr(
                    node.left
                ) or self._is_string_building_expr(node.right)
            if isinstance(node.op, ast.Mod):
                return isinstance(node.left, ast.Constant) and isinstance(
                    node.left.value, str
                )
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                return True
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return True
        return False

    def _is_external_input_expr(
        self, node: ast.AST, tainted_names: Set[str], aliases: Dict[str, str]
    ) -> bool:
        """式が外部入力由来（または tainted 変数由来）かを再帰的に判定する。"""
        if isinstance(node, ast.Name):
            return node.id in tainted_names

        if isinstance(node, ast.Subscript):
            target_name = self._resolve_name(self._full_name(node.value), aliases)
            if target_name in {"sys.argv", "os.environ", "environ"}:
                return True

        if isinstance(node, ast.Attribute):
            full = self._resolve_name(self._full_name(node), aliases)
            return bool(full and full.startswith("request."))

        if isinstance(node, ast.Call):
            callee = self._resolve_name(self._full_name(node.func), aliases)
            if callee in self._EXTERNAL_SOURCE_CALLS:
                return True
            if callee and callee.startswith("request."):
                return True

        for child in ast.iter_child_nodes(node):
            if self._is_external_input_expr(child, tainted_names, aliases):
                return True

        return False

    @staticmethod
    def _iter_assigned_names(target: ast.AST) -> Iterable[str]:
        if isinstance(target, ast.Name):
            yield target.id
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                yield from A1CommandInjectionRule._iter_assigned_names(elt)

    def _collect_tainted_names(
        self, tree: ast.AST, aliases: Dict[str, str]
    ) -> Set[str]:
        """代入解析を繰り返し、外部入力由来の変数名集合を収集する。"""
        tainted: Set[str] = set()

        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    if self._is_external_input_expr(node.value, tainted, aliases):
                        for target in node.targets:
                            for name in self._iter_assigned_names(target):
                                if name not in tainted:
                                    tainted.add(name)
                                    changed = True
                    continue

                if isinstance(node, ast.AnnAssign):
                    if node.value and self._is_external_input_expr(
                        node.value, tainted, aliases
                    ):
                        for name in self._iter_assigned_names(node.target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
                    continue

                if isinstance(node, ast.AugAssign):
                    if self._is_external_input_expr(node.value, tainted, aliases):
                        for name in self._iter_assigned_names(node.target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
                    continue

                if isinstance(node, ast.For):
                    if self._is_external_input_expr(node.iter, tainted, aliases):
                        for name in self._iter_assigned_names(node.target):
                            if name not in tainted:
                                tainted.add(name)
                                changed = True
        return tainted

    @staticmethod
    def _literal_bool(node: ast.AST, bool_bindings: Dict[str, bool]) -> Optional[bool]:
        if isinstance(node, ast.Constant) and isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.Name):
            return bool_bindings.get(node.id)
        return None

    def _shell_true(self, call: ast.Call, bool_bindings: Dict[str, bool]) -> bool:
        """subprocess 呼び出しで shell=True が明示されているか判定する。"""
        for kw in call.keywords:
            if kw.arg == "shell":
                value = self._literal_bool(kw.value, bool_bindings)
                return value is True
        return False

    def _collect_bool_bindings(self, tree: ast.AST) -> Dict[str, bool]:
        """shell=True 判定補助のため、単純な bool 代入を収集する。"""
        bindings: Dict[str, bool] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                if isinstance(target, ast.Name):
                    value = self._literal_bool(node.value, bindings)
                    if value is not None:
                        bindings[target.id] = value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.value is None:
                    continue
                value = self._literal_bool(node.value, bindings)
                if value is not None:
                    bindings[node.target.id] = value
        return bindings

    @staticmethod
    def _extract_command_arg(call: ast.Call) -> Optional[ast.AST]:
        """subprocess 系呼び出しからコマンド実体の AST を取り出す。"""
        if call.args:
            return call.args[0]
        for kw in call.keywords:
            if kw.arg in A1CommandInjectionRule._SUBPROCESS_CMD_KWARGS:
                return kw.value
        return None

    def _collect_wrapper_sinks(
        self,
        tree: ast.AST,
        aliases: Dict[str, str],
    ) -> Set[str]:
        """危険コールを内包する自作ラッパー関数名を収集する。"""
        wrappers: Set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                callee = self._resolve_name(self._full_name(child.func), aliases)
                if callee in self._DANGEROUS_CALLS:
                    wrappers.add(node.name)
                    break
        return wrappers

    @staticmethod
    def _contains_tainted_token(text: str, tainted_names: Set[str]) -> bool:
        for name in tainted_names:
            if re.search(rf"\b{re.escape(name)}\b", text):
                return True
        return False

    def _js_has_external_input(self, text: str, tainted_names: Set[str]) -> bool:
        if any(token in text for token in self._JS_EXTERNAL_SOURCE_TOKENS):
            return True
        return self._contains_tainted_token(text, tainted_names)

    def _evaluate_js_ts_file(self, file_path: Path, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        rel_path = str(file_path.relative_to(target))
        try:
            src = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return records

        tainted_names: Set[str] = set()
        lines = src.splitlines()

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue

            m = re.search(
                r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$", stripped
            )
            if m:
                var_name, rhs = m.group(1), m.group(2)
                if self._js_has_external_input(rhs, tainted_names):
                    tainted_names.add(var_name)

            if re.search(r"\b(?:exec|execSync)\s*\(", stripped):
                if self._js_has_external_input(stripped, tainted_names):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=i,
                            message="外部入力を child_process のコマンド文字列実行に渡しています",
                        )
                    )
                continue

            if re.search(r"\b(?:spawn|spawnSync)\s*\(", stripped):
                if not self._js_has_external_input(stripped, tainted_names):
                    continue
                has_shell_true = "shell: true" in stripped or "shell:true" in stripped
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH if has_shell_true else Severity.MEDIUM,
                        file_path=rel_path,
                        line=i,
                        message=(
                            "外部入力を shell=true の spawn 系実行に渡しています"
                            if has_shell_true
                            else "外部入力を spawn 系プロセス実行に渡しています"
                        ),
                    )
                )

        return records

    @staticmethod
    def _shell_expands_external_input(line: str, tainted_names: Set[str]) -> bool:
        if re.search(r"\$[0-9@*]", line) or re.search(r"\$\{[0-9]+\}", line):
            return True

        for name in tainted_names:
            if re.search(rf"\$(?:\{{)?{re.escape(name)}(?:\}})?\b", line):
                return True
        return False

    def _evaluate_shell_file(self, file_path: Path, target: Path) -> List[RiskRecord]:
        records: List[RiskRecord] = []
        rel_path = str(file_path.relative_to(target))
        try:
            src = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return records

        tainted_names: Set[str] = set()
        lines = src.splitlines()

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            read_match = re.search(
                r"\bread\b(?:\s+-\w+)*\s+([A-Za-z_][A-Za-z0-9_]*)", stripped
            )
            if read_match:
                tainted_names.add(read_match.group(1))

            assign_match = re.search(r"^([A-Za-z_][A-Za-z0-9_]*)=(.+)$", stripped)
            if assign_match:
                var_name, rhs = assign_match.group(1), assign_match.group(2)
                if self._shell_expands_external_input(rhs, tainted_names):
                    tainted_names.add(var_name)

            has_external = self._shell_expands_external_input(stripped, tainted_names)
            if not has_external:
                continue

            if re.search(r"\beval\b", stripped):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=i,
                        message="外部入力を含む式を eval で実行しています",
                    )
                )
                continue

            if re.search(r"\b(?:sh|bash|zsh|ksh)\s+-c\b", stripped):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=i,
                        message="外部入力を含むコマンド文字列を shell -c で実行しています",
                    )
                )
                continue

            if re.search(r"`[^`]*\$[^`]*`", stripped):
                records.append(
                    RiskRecord(
                        rule_id=self.rule_id,
                        category=self.category,
                        title=self.title,
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line=i,
                        message="外部入力を含むコマンド置換（バッククォート）を使用しています",
                    )
                )

        return records

    def evaluate(self, target: Path) -> List[RiskRecord]:
        """対象コードを走査し、コマンドインジェクション疑いを RiskRecord として返す。"""
        records: List[RiskRecord] = []

        for py_file in self._iter_python_files(target):
            try:
                src = py_file.read_text(encoding="utf-8")
                tree = ast.parse(src)
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue

            aliases = self._collect_import_aliases(tree)
            tainted_names = self._collect_tainted_names(tree, aliases)
            wrapper_sinks = self._collect_wrapper_sinks(tree, aliases)
            bool_bindings = self._collect_bool_bindings(tree)
            rel_path = str(py_file.relative_to(target))

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue

                callee = self._resolve_name(self._full_name(node.func), aliases)
                is_wrapper_sink = bool(callee and callee in wrapper_sinks)
                if callee not in self._DANGEROUS_CALLS and not is_wrapper_sink:
                    continue

                first_arg = self._extract_command_arg(node)
                if first_arg is None:
                    continue

                has_external = self._is_external_input_expr(
                    first_arg, tainted_names, aliases
                )
                is_string_build = self._is_string_building_expr(first_arg)

                if callee in self._SHELL_LIKE_CALLS:
                    if has_external and (
                        is_string_build
                        or isinstance(
                            first_arg,
                            (
                                ast.Name,
                                ast.Subscript,
                                ast.Call,
                            ),
                        )
                    ):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=getattr(node, "lineno", None),
                                message="外部入力を用いたコマンド文字列をシェル実行しています",
                            )
                        )
                    continue

                if callee in {"os.spawnl", "os.spawnlp", "os.spawnv", "os.spawnvp"}:
                    if has_external:
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=getattr(node, "lineno", None),
                                message="外部入力を用いた引数でプロセス実行APIを呼び出しています",
                            )
                        )
                    continue

                if is_wrapper_sink:
                    if has_external and (
                        is_string_build or isinstance(first_arg, ast.Name)
                    ):
                        records.append(
                            RiskRecord(
                                rule_id=self.rule_id,
                                category=self.category,
                                title=self.title,
                                severity=Severity.HIGH,
                                file_path=rel_path,
                                line=getattr(node, "lineno", None),
                                message="外部入力を危険なコマンド実行ラッパー関数へ渡しています",
                            )
                        )
                    continue

                # subprocess.*
                shell_true = self._shell_true(node, bool_bindings)
                if has_external and shell_true and is_string_build:
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line=getattr(node, "lineno", None),
                            message="外部入力を用いてシェルコマンドを組み立てて実行しています",
                        )
                    )
                    continue

                if (
                    has_external
                    and isinstance(first_arg, ast.Constant)
                    and isinstance(first_arg.value, str)
                ):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=getattr(node, "lineno", None),
                            message="外部入力を含む可能性がある文字列コマンドを subprocess に渡しています",
                        )
                    )
                    continue

                if (
                    has_external
                    and not shell_true
                    and isinstance(first_arg, (ast.List, ast.Tuple))
                ):
                    records.append(
                        RiskRecord(
                            rule_id=self.rule_id,
                            category=self.category,
                            title=self.title,
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line=getattr(node, "lineno", None),
                            message="外部入力をコマンド引数に使用しています。引数の妥当性確認が必要です",
                        )
                    )

        for js_file in self._iter_js_ts_files(target):
            records.extend(self._evaluate_js_ts_file(js_file, target))

        for shell_file in self._iter_shell_files(target):
            records.extend(self._evaluate_shell_file(shell_file, target))

        return records
