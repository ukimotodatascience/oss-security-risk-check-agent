import ast
import re
from typing import Dict, Optional, Set

from src.rules.A_code.A1_2_1_command_injection_python_taint import PythonTaintMixin


class PythonSinkMixin(PythonTaintMixin):
    _DANGEROUS_CALLS = {
        "os.system",
        "os.popen",
        "os.spawnl",
        "os.spawnlp",
        "os.spawnv",
        "os.spawnvp",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "asyncio.create_subprocess_shell",
        "pty.spawn",
        "platform.popen",
    }
    _SHELL_LIKE_CALLS = {
        "os.system",
        "os.popen",
        "asyncio.create_subprocess_shell",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "platform.popen",
    }
    _PROCESS_EXEC_CALLS = {
        "os.spawnl",
        "os.spawnlp",
        "os.spawnv",
        "os.spawnvp",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "pty.spawn",
    }
    _SUBPROCESS_CMD_KWARGS = {"args", "cmd", "command"}

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
        for node in self._walk_scope_nodes(tree):
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
            if kw.arg in PythonSinkMixin._SUBPROCESS_CMD_KWARGS:
                return kw.value
        return None

    def _collect_wrapper_sinks(
        self,
        tree: ast.AST,
        aliases: Dict[str, str],
    ) -> Dict[str, Set[int]]:
        """危険コールへ流れる引数位置を持つ自作ラッパー関数を収集する。"""
        wrappers: Dict[str, Set[int]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            param_positions = {arg.arg: i for i, arg in enumerate(node.args.args)}
            sink_positions: Set[int] = set()
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                callee = self._resolve_name(self._full_name(child.func), aliases)
                if callee not in self._DANGEROUS_CALLS:
                    continue
                command_arg = self._extract_command_arg(child)
                if command_arg is None:
                    continue
                command_text = (
                    ast.unparse(command_arg) if hasattr(ast, "unparse") else ""
                )
                if isinstance(command_arg, ast.Constant):
                    continue
                for param, position in param_positions.items():
                    if re.search(rf"\b{re.escape(param)}\b", command_text):
                        sink_positions.add(position)
            if sink_positions:
                wrappers[node.name] = sink_positions
        return wrappers

    def _wrapper_has_external_arg(
        self,
        call: ast.Call,
        sink_positions: Set[int],
        tainted_names: Set[str],
        aliases: Dict[str, str],
        taint_returning_functions: Set[str],
    ) -> bool:
        for position in sink_positions:
            if position < len(call.args) and self._is_external_input_expr(
                call.args[position], tainted_names, aliases, taint_returning_functions
            ):
                return True
        return False
