from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class DependencyDecl:
    name: str
    spec: str
    file_path: str
    line: Optional[int] = None
    ecosystem: str = "python"


_REQ_SPLIT = re.compile(r"\s*(==|===|~=|!=|<=|>=|<|>|@|\^|~)\s*")
_VERSION_TOKEN = re.compile(r"(\d+(?:\.\d+)*)")


def normalize_name(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def parse_requirements_file(path: Path, target: Path) -> List[DependencyDecl]:
    records: List[DependencyDecl] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return records

    rel = str(path.relative_to(target))
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split(" #", 1)[0].strip()
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            continue

        m = _REQ_SPLIT.split(line, maxsplit=1)
        if not m:
            continue
        name = m[0].strip()
        if not name or name.startswith(("git+", "http://", "https://", "file:")):
            continue
        spec = ""
        if len(m) >= 3:
            spec = f"{m[1]}{m[2].strip()}"

        records.append(
            DependencyDecl(
                name=normalize_name(name),
                spec=spec,
                file_path=rel,
                line=i,
                ecosystem="python",
            )
        )
    return records


def parse_package_json(path: Path, target: Path) -> List[DependencyDecl]:
    records: List[DependencyDecl] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return records

    rel = str(path.relative_to(target))
    for field in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(spec, str):
                continue
            records.append(
                DependencyDecl(
                    name=normalize_name(name),
                    spec=spec.strip(),
                    file_path=rel,
                    ecosystem="node",
                )
            )
    return records


def collect_dependency_declarations(target: Path) -> List[DependencyDecl]:
    decls: List[DependencyDecl] = []

    for req in target.rglob("requirements*.txt"):
        if req.is_file():
            decls.extend(parse_requirements_file(req, target))

    for pkg in target.rglob("package.json"):
        if pkg.is_file() and "node_modules" not in pkg.parts:
            decls.extend(parse_package_json(pkg, target))

    return decls


def parse_version_tuple(spec: str) -> Optional[Tuple[int, ...]]:
    m = _VERSION_TOKEN.search(spec)
    if not m:
        return None
    try:
        return tuple(int(x) for x in m.group(1).split("."))
    except ValueError:
        return None


def is_pinned(dep: DependencyDecl) -> bool:
    s = dep.spec.strip()
    if not s:
        return False
    if dep.ecosystem == "python":
        return s.startswith("==") or s.startswith("===")

    # Node.js: exact semver like 1.2.3
    return bool(re.fullmatch(r"\d+\.\d+\.\d+", s))


def is_loose_spec(dep: DependencyDecl) -> bool:
    s = dep.spec.strip().lower()
    if not s:
        return True
    loose_tokens = ("*", "latest", "^", "~", ">", "<", "x", "||", " - ")
    if any(t in s for t in loose_tokens):
        return True
    if dep.ecosystem == "python":
        return not (s.startswith("==") or s.startswith("==="))
    return not bool(re.fullmatch(r"\d+\.\d+\.\d+", s))


def collect_python_imports(target: Path) -> Set[str]:
    imported: Set[str] = set()
    for py in target.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported.add(alias.name.split(".", 1)[0].lower())
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0].lower())
    return imported


def collect_js_imports(target: Path) -> Set[str]:
    imported: Set[str] = set()
    pattern = re.compile(
        r"(?:import\s+.*?\s+from\s+|require\()\s*['\"](?P<name>@?[a-zA-Z0-9_.\-/]+)['\"]"
    )
    for ext in ("*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs"):
        for f in target.rglob(ext):
            if "node_modules" in f.parts:
                continue
            try:
                text = f.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for m in pattern.finditer(text):
                name = m.group("name")
                if name.startswith("."):
                    continue
                if name.startswith("@"):
                    parts = name.split("/")
                    pkg = "/".join(parts[:2]) if len(parts) >= 2 else name
                else:
                    pkg = name.split("/", 1)[0]
                imported.add(normalize_name(pkg))
    return imported


def discover_lockfiles(target: Path) -> Set[str]:
    present: Set[str] = set()
    names = {
        "poetry.lock",
        "Pipfile.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "uv.lock",
    }
    for p in target.rglob("*"):
        if p.is_file() and p.name in names:
            present.add(p.name)
    return present


def has_file(target: Path, name: str) -> bool:
    return any(p.is_file() and p.name == name for p in target.rglob(name))
