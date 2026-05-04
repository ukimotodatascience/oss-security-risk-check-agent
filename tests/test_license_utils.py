from __future__ import annotations

from src.rules.K_license._license_utils import (
    DependencyLicense,
    _collect_from_package_lock,
    _collect_from_poetry_lock,
    build_dependency_license_map,
    collect_dependency_licenses,
    collect_project_license_expressions,
    extract_spdx_like_tokens,
    find_license_files,
    normalize_license,
)


def test_normalize_and_extract_spdx_like_tokens():
    assert normalize_license("  MIT   OR   Apache-2.0  ") == "MIT OR Apache-2.0"
    assert extract_spdx_like_tokens("MIT OR Apache-2.0 WITH LLVM-exception") == {
        "MIT",
        "APACHE-2.0",
        "LLVM-EXCEPTION",
    }
    assert extract_spdx_like_tokens("see LICENSE in repo") == {"REPO"}
    assert extract_spdx_like_tokens("") == set()


def test_find_license_files_discovers_known_names_only(tmp_path):
    (tmp_path / "LICENSE").write_text("MIT", encoding="utf-8")
    (tmp_path / "COPYING.md").write_text("GPL", encoding="utf-8")
    (tmp_path / "license-lowercase").write_text("ignored", encoding="utf-8")
    (tmp_path / "docs").mkdir()

    found = {p.name for p in find_license_files(tmp_path)}

    assert found == {"LICENSE", "COPYING.md"}


def test_collect_project_license_expressions_from_package_json_and_pyproject(tmp_path):
    (tmp_path / "package.json").write_text(
        """
        {
          "license": " MIT ",
          "licenses": [
            {"type": "Apache-2.0"},
            {"license": "BSD-3-Clause"},
            "ignored"
          ]
        }
        """,
        encoding="utf-8",
    )
    node_modules = tmp_path / "node_modules" / "pkg"
    node_modules.mkdir(parents=True)
    (node_modules / "package.json").write_text(
        '{"license": "GPL-3.0"}', encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text(
        """
        [project]
        license = "Proprietary"
        [tool.demo]
        license = { text = "MPL-2.0" }
        """,
        encoding="utf-8",
    )

    assert collect_project_license_expressions(tmp_path) == [
        ("package.json", "MIT"),
        ("package.json", "Apache-2.0"),
        ("package.json", "BSD-3-Clause"),
        ("pyproject.toml", "Proprietary"),
        ("pyproject.toml", "MPL-2.0"),
    ]


def test_collect_project_license_expressions_ignores_invalid_files(tmp_path):
    (tmp_path / "package.json").write_text("{", encoding="utf-8")
    assert collect_project_license_expressions(tmp_path) == []


def test_collect_from_package_lock_reads_packages_and_dependencies(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """
        {
          "packages": {
            "": {"license": "MIT"},
            "node_modules/react": {"license": "MIT"},
            "node_modules/@scope/pkg": {"license": "Apache-2.0"},
            "node_modules/no-license": {},
            "custom": {"name": "custom-name", "license": "BSD-2-Clause"}
          },
          "dependencies": {
            "left-pad": {"license": "WTFPL"},
            "bad": "ignored"
          }
        }
        """,
        encoding="utf-8",
    )

    records = _collect_from_package_lock(lock, tmp_path)

    assert records == [
        DependencyLicense("react", "MIT", "package-lock.json"),
        DependencyLicense("@scope/pkg", "Apache-2.0", "package-lock.json"),
        DependencyLicense("custom-name", "BSD-2-Clause", "package-lock.json"),
        DependencyLicense("left-pad", "WTFPL", "package-lock.json"),
    ]


def test_collect_from_package_lock_returns_empty_for_invalid_json(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text("{", encoding="utf-8")
    assert _collect_from_package_lock(lock, tmp_path) == []


def test_collect_from_poetry_lock_tracks_package_license_lines(tmp_path):
    lock = tmp_path / "poetry.lock"
    lock.write_text(
        """
        [[package]]
        name = "requests"
        version = "2.31.0"
        license = "Apache-2.0"

        [[package]]
        license = "MIT"
        name = "late-name"

        [[package]]
        name = "empty"
        license = ""
        """,
        encoding="utf-8",
    )

    records = _collect_from_poetry_lock(lock, tmp_path)

    assert records == [
        DependencyLicense("requests", "Apache-2.0", "poetry.lock", 5),
    ]


def test_collect_dependency_licenses_merges_and_deduplicates(tmp_path):
    (tmp_path / "package-lock.json").write_text(
        """
        {
          "packages": {
            "node_modules/react": {"license": "MIT"},
            "node_modules/react-copy": {"name": "react", "license": "mit"}
          },
          "dependencies": {
            "left-pad": {"license": "WTFPL"}
          }
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "poetry.lock").write_text(
        """
        [[package]]
        name = "requests"
        license = "Apache-2.0"
        """,
        encoding="utf-8",
    )
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    (node_modules / "package-lock.json").write_text(
        '{"dependencies": {"ignored": {"license": "GPL-3.0"}}}', encoding="utf-8"
    )

    records = collect_dependency_licenses(tmp_path)

    assert records == [
        DependencyLicense("react", "MIT", "package-lock.json"),
        DependencyLicense("left-pad", "WTFPL", "package-lock.json"),
        DependencyLicense("requests", "Apache-2.0", "poetry.lock", 4),
    ]


def test_build_dependency_license_map_keeps_first_non_empty_license():
    entries = [
        DependencyLicense("pkg", "", "a"),
        DependencyLicense("pkg", "MIT", "b"),
        DependencyLicense("pkg", "Apache-2.0", "c"),
        DependencyLicense("other", "BSD-3-Clause", "d"),
    ]

    assert build_dependency_license_map(entries) == {
        "pkg": "MIT",
        "other": "BSD-3-Clause",
    }
