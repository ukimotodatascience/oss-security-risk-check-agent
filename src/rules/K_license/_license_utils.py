from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class DependencyLicense:
    package: str
    license_expr: str
    file_path: str
    line: Optional[int] = None


_SPDX_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9.+-]*")
_POETRY_PACKAGE_NAME = re.compile(r'^name\s*=\s*"(?P<name>[^"]+)"\s*$')
_POETRY_PACKAGE_LICENSE = re.compile(r'^license\s*=\s*"(?P<license>[^"]*)"\s*$')
_PYPROJECT_LICENSE_INLINE = re.compile(r"(?m)^\s*license\s*=\s*['\"]([^'\"]+)['\"]\s*$")
_PYPROJECT_LICENSE_TEXT = re.compile(
    r"(?m)^\s*license\s*=\s*\{[^}]*text\s*=\s*['\"]([^'\"]+)['\"][^}]*\}\s*$"
)


def normalize_license(expr: str) -> str:
    return re.sub(r"\s+", " ", expr.strip())


def extract_spdx_like_tokens(expr: str) -> Set[str]:
    if not expr:
        return set()
    tokens: Set[str] = set()
    for token in _SPDX_TOKEN.findall(expr):
        upper = token.upper()
        if upper in {"AND", "OR", "WITH", "LICENSE", "SEE", "IN"}:
            continue
        tokens.add(upper)
    return tokens


def find_license_files(target: Path) -> List[Path]:
    candidates = {
        "LICENSE",
        "LICENSE.txt",
        "LICENSE.md",
        "COPYING",
        "COPYING.txt",
        "COPYING.md",
        "UNLICENSE",
    }
    found: List[Path] = []
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        if p.name in candidates:
            found.append(p)
    return found


def collect_project_license_expressions(target: Path) -> List[Tuple[str, str]]:
    found: List[Tuple[str, str]] = []

    for pkg in target.rglob("package.json"):
        if "node_modules" in pkg.parts or not pkg.is_file():
            continue
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue

        lic = data.get("license")
        if isinstance(lic, str) and lic.strip():
            found.append((str(pkg.relative_to(target)), normalize_license(lic)))

        licenses = data.get("licenses")
        if isinstance(licenses, list):
            for item in licenses:
                if isinstance(item, dict):
                    val = item.get("type") or item.get("license")
                    if isinstance(val, str) and val.strip():
                        found.append(
                            (str(pkg.relative_to(target)), normalize_license(val))
                        )

    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        if text:
            for m in _PYPROJECT_LICENSE_INLINE.finditer(text):
                found.append(("pyproject.toml", normalize_license(m.group(1))))
            for m in _PYPROJECT_LICENSE_TEXT.finditer(text):
                found.append(("pyproject.toml", normalize_license(m.group(1))))

    return found


def _collect_from_package_lock(
    lock_file: Path, target: Path
) -> List[DependencyLicense]:
    records: List[DependencyLicense] = []
    try:
        data = json.loads(lock_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return records

    rel = str(lock_file.relative_to(target))

    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, obj in packages.items():
            if not isinstance(obj, dict):
                continue
            lic = obj.get("license")
            if not isinstance(lic, str) or not lic.strip():
                continue

            name = obj.get("name")
            if not isinstance(name, str) or not name.strip():
                if isinstance(key, str) and key.startswith("node_modules/"):
                    name = key.split("node_modules/", 1)[1]
                else:
                    continue
            records.append(
                DependencyLicense(
                    package=name.strip().lower(),
                    license_expr=normalize_license(lic),
                    file_path=rel,
                    line=None,
                )
            )

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        for name, obj in deps.items():
            if not isinstance(name, str) or not isinstance(obj, dict):
                continue
            lic = obj.get("license")
            if isinstance(lic, str) and lic.strip():
                records.append(
                    DependencyLicense(
                        package=name.strip().lower(),
                        license_expr=normalize_license(lic),
                        file_path=rel,
                        line=None,
                    )
                )

    return records


def _collect_from_poetry_lock(lock_file: Path, target: Path) -> List[DependencyLicense]:
    records: List[DependencyLicense] = []
    try:
        lines = lock_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return records

    rel = str(lock_file.relative_to(target))
    current_name: Optional[str] = None
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if line == "[[package]]":
            current_name = None
            continue

        m_name = _POETRY_PACKAGE_NAME.match(line)
        if m_name:
            current_name = m_name.group("name").strip().lower()
            continue

        m_license = _POETRY_PACKAGE_LICENSE.match(line)
        if m_license and current_name:
            lic = normalize_license(m_license.group("license"))
            if lic:
                records.append(
                    DependencyLicense(
                        package=current_name,
                        license_expr=lic,
                        file_path=rel,
                        line=i,
                    )
                )

    return records


def collect_dependency_licenses(target: Path) -> List[DependencyLicense]:
    records: List[DependencyLicense] = []

    for lock_file in target.rglob("package-lock.json"):
        if lock_file.is_file() and "node_modules" not in lock_file.parts:
            records.extend(_collect_from_package_lock(lock_file, target))

    for lock_file in target.rglob("poetry.lock"):
        if lock_file.is_file():
            records.extend(_collect_from_poetry_lock(lock_file, target))

    unique: List[DependencyLicense] = []
    seen: Set[Tuple[str, str, str]] = set()
    for rec in records:
        key = (rec.package, rec.license_expr.upper(), rec.file_path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(rec)

    return unique


def build_dependency_license_map(
    entries: Sequence[DependencyLicense],
) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for e in entries:
        if e.package not in out and e.license_expr:
            out[e.package] = e.license_expr
    return out
