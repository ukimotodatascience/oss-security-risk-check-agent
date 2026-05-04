from __future__ import annotations

from src.rules.B_dependencies._dependency_utils import (
    DependencyDecl,
    collect_dependency_declarations,
    collect_js_imports,
    collect_python_imports,
    discover_lockfiles,
    has_file,
    is_loose_spec,
    is_pinned,
    normalize_name,
    parse_package_json,
    parse_requirements_file,
    parse_version_tuple,
)


def test_parse_requirements_file_handles_common_lines(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "\n"
        "# comment\n"
        "Requests==2.31.0 # inline comment\n"
        "django>=4\n"
        "-r base.txt\n"
        "git+https://example.com/repo.git\n"
        "local-package @ file:///tmp/pkg\n",
        encoding="utf-8",
    )

    decls = parse_requirements_file(req, tmp_path)

    assert decls == [
        DependencyDecl("requests", "==2.31.0", "requirements.txt", 3, "python"),
        DependencyDecl("django", ">=4", "requirements.txt", 4, "python"),
        DependencyDecl(
            "local-package", "@file:///tmp/pkg", "requirements.txt", 7, "python"
        ),
    ]


def test_parse_requirements_file_returns_empty_for_unreadable_content(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_bytes(b"\xff\xfe\x00")

    assert parse_requirements_file(req, tmp_path) == []


def test_parse_package_json_reads_all_dependency_sections(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        """
        {
          "dependencies": {"react": "18.2.0"},
          "devDependencies": {"vite": "^5.0.0"},
          "optionalDependencies": {"fsevents": "~2.3.0"},
          "peerDependencies": {"typescript": ">=5"},
          "badDependencies": {"bad": 1}
        }
        """,
        encoding="utf-8",
    )

    decls = parse_package_json(pkg, tmp_path)

    assert {(d.name, d.spec, d.ecosystem) for d in decls} == {
        ("react", "18.2.0", "node"),
        ("vite", "^5.0.0", "node"),
        ("fsevents", "~2.3.0", "node"),
        ("typescript", ">=5", "node"),
    }


def test_parse_package_json_returns_empty_for_invalid_json(tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text("{", encoding="utf-8")

    assert parse_package_json(pkg, tmp_path) == []


def test_collect_dependency_declarations_skips_node_modules(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"left-pad": "1.3.0"}}', encoding="utf-8"
    )
    node_modules = tmp_path / "node_modules" / "pkg"
    node_modules.mkdir(parents=True)
    (node_modules / "package.json").write_text(
        '{"dependencies": {"ignored": "1.0.0"}}', encoding="utf-8"
    )

    decls = collect_dependency_declarations(tmp_path)

    assert {(d.name, d.ecosystem) for d in decls} == {
        ("pytest", "python"),
        ("left-pad", "node"),
    }


def test_version_and_spec_helpers():
    assert normalize_name(" My_Package ") == "my-package"
    assert parse_version_tuple("==1.2.3") == (1, 2, 3)
    assert parse_version_tuple("latest") is None
    assert is_pinned(DependencyDecl("requests", "==2.31.0", "requirements.txt"))
    assert is_pinned(
        DependencyDecl("react", "18.2.0", "package.json", ecosystem="node")
    )
    assert not is_pinned(
        DependencyDecl("react", "^18.2.0", "package.json", ecosystem="node")
    )
    assert is_loose_spec(DependencyDecl("django", ">=4", "requirements.txt"))
    assert is_loose_spec(
        DependencyDecl("vite", "latest", "package.json", ecosystem="node")
    )
    assert not is_loose_spec(DependencyDecl("flask", "==3.0.0", "requirements.txt"))


def test_collect_python_imports_handles_import_forms_and_syntax_errors(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\nimport requests.sessions\nfrom flask import Flask\n",
        encoding="utf-8",
    )
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    assert collect_python_imports(tmp_path) == {"os", "requests", "flask"}


def test_collect_js_imports_handles_scopes_and_ignores_relative_and_node_modules(
    tmp_path,
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.ts").write_text(
        "import React from 'react';\n"
        "import x from './local';\n"
        "const express = require('express/lib/router');\n"
        "const scoped = require('@scope/pkg/subpath');\n",
        encoding="utf-8",
    )
    node_modules = tmp_path / "node_modules" / "ignored"
    node_modules.mkdir(parents=True)
    (node_modules / "index.js").write_text("require('ignored')", encoding="utf-8")

    assert collect_js_imports(tmp_path) == {"react", "express", "@scope/pkg"}


def test_discover_lockfiles_and_has_file(tmp_path):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "poetry.lock").write_text("", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs", encoding="utf-8")

    assert discover_lockfiles(tmp_path) == {"poetry.lock", "package-lock.json"}
    assert has_file(tmp_path, "README.md")
    assert not has_file(tmp_path, "SECURITY.md")
