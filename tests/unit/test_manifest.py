"""Unit tests for manifest file parsers (scan_file mode)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentshield.core.manifest import (
    detect_format,
    parse_cargo_toml,
    parse_manifest,
    parse_package_json,
    parse_package_lock_json,
    parse_requirements_txt,
)
from agentshield.core.models import Ecosystem

# ── detect_format ─────────────────────────────────────────────────────────────


def test_detect_format_requirements_txt(tmp_path: Path) -> None:
    p = tmp_path / "requirements.txt"
    p.write_text("")
    assert detect_format(p) == "requirements_txt"


def test_detect_format_package_json(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text("{}")
    assert detect_format(p) == "package_json"


def test_detect_format_cargo_toml(tmp_path: Path) -> None:
    p = tmp_path / "Cargo.toml"
    p.write_text("")
    assert detect_format(p) == "cargo_toml"


def test_detect_format_package_lock_json(tmp_path: Path) -> None:
    p = tmp_path / "package-lock.json"
    p.write_text("{}")
    assert detect_format(p) == "package_lock_json"


def test_detect_format_unknown_raises(tmp_path: Path) -> None:
    p = tmp_path / "setup.py"
    p.write_text("")
    with pytest.raises(ValueError, match="Unrecognized manifest filename"):
        detect_format(p)


# ── parse_requirements_txt ───────────────────────────────────────────────────


def _req_txt(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text(content)
    return p


def test_requirements_txt_pinned_version(tmp_path: Path) -> None:
    p = _req_txt(tmp_path, "requests==2.31.0\n")
    reqs = parse_requirements_txt(p)
    assert len(reqs) == 1
    assert reqs[0].package == "requests"
    assert reqs[0].version == "2.31.0"
    assert reqs[0].ecosystem == Ecosystem.PYPI


def test_requirements_txt_range_no_pin(tmp_path: Path) -> None:
    p = _req_txt(tmp_path, "flask>=2.0,<3.0\n")
    reqs = parse_requirements_txt(p)
    assert len(reqs) == 1
    assert reqs[0].package == "flask"
    assert reqs[0].version is None


def test_requirements_txt_bare_package(tmp_path: Path) -> None:
    p = _req_txt(tmp_path, "numpy\n")
    reqs = parse_requirements_txt(p)
    assert len(reqs) == 1
    assert reqs[0].package == "numpy"
    assert reqs[0].version is None


def test_requirements_txt_skips_comments(tmp_path: Path) -> None:
    content = "# This is a comment\nrequests==2.31.0\n"
    reqs = parse_requirements_txt(_req_txt(tmp_path, content))
    assert len(reqs) == 1
    assert reqs[0].package == "requests"


def test_requirements_txt_skips_flags(tmp_path: Path) -> None:
    content = "-r other.txt\n--index-url https://pypi.org/simple\nrequests==2.31.0\n"
    reqs = parse_requirements_txt(_req_txt(tmp_path, content))
    assert len(reqs) == 1
    assert reqs[0].package == "requests"


def test_requirements_txt_skips_urls(tmp_path: Path) -> None:
    content = "https://example.com/mypackage.tar.gz\nrequests==2.31.0\n"
    reqs = parse_requirements_txt(_req_txt(tmp_path, content))
    assert len(reqs) == 1


def test_requirements_txt_strips_env_markers(tmp_path: Path) -> None:
    content = 'flask>=2.0 ; python_version >= "3.6"\n'
    reqs = parse_requirements_txt(_req_txt(tmp_path, content))
    assert len(reqs) == 1
    assert reqs[0].package == "flask"
    assert reqs[0].version is None


def test_requirements_txt_multiple_packages(tmp_path: Path) -> None:
    content = "requests==2.31.0\nflask==2.3.0\nnumpy\n"
    reqs = parse_requirements_txt(_req_txt(tmp_path, content))
    assert len(reqs) == 3
    names = [r.package for r in reqs]
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names


def test_requirements_txt_empty_file(tmp_path: Path) -> None:
    p = _req_txt(tmp_path, "")
    assert parse_requirements_txt(p) == []


# ── parse_package_json ────────────────────────────────────────────────────────


def _pkg_json(tmp_path: Path, data: dict) -> Path:  # type: ignore[type-arg]
    p = tmp_path / "package.json"
    p.write_text(json.dumps(data))
    return p


def test_package_json_dependencies(tmp_path: Path) -> None:
    data = {"dependencies": {"express": "^4.18.0", "lodash": "4.17.21"}}
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert len(reqs) == 2
    names = {r.package for r in reqs}
    assert names == {"express", "lodash"}
    assert all(r.ecosystem == Ecosystem.NPM for r in reqs)


def test_package_json_dev_dependencies(tmp_path: Path) -> None:
    data = {"devDependencies": {"jest": "^29.0.0"}}
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert len(reqs) == 1
    assert reqs[0].package == "jest"


def test_package_json_both_sections(tmp_path: Path) -> None:
    data = {
        "dependencies": {"react": "^18.0.0"},
        "devDependencies": {"typescript": "~5.0.0"},
    }
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert len(reqs) == 2


def test_package_json_pinned_version_extracted(tmp_path: Path) -> None:
    data = {"dependencies": {"lodash": "4.17.21"}}
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert reqs[0].version == "4.17.21"


def test_package_json_caret_version_stripped(tmp_path: Path) -> None:
    data = {"dependencies": {"express": "^4.18.0"}}
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert reqs[0].version == "4.18.0"


def test_package_json_tilde_version_stripped(tmp_path: Path) -> None:
    data = {"dependencies": {"lodash": "~4.17.0"}}
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert reqs[0].version == "4.17.0"


def test_package_json_star_version_is_none(tmp_path: Path) -> None:
    data = {"dependencies": {"some-pkg": "*"}}
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert reqs[0].version is None


def test_package_json_empty_sections(tmp_path: Path) -> None:
    data = {"name": "myapp", "version": "1.0.0"}
    reqs = parse_package_json(_pkg_json(tmp_path, data))
    assert reqs == []


# ── parse_cargo_toml ──────────────────────────────────────────────────────────


def _cargo_toml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "Cargo.toml"
    p.write_text(content)
    return p


def test_cargo_toml_dependencies(tmp_path: Path) -> None:
    content = '[dependencies]\nserde = "1.0"\ntokio = { version = "1.0", features = ["full"] }\n'
    reqs = parse_cargo_toml(_cargo_toml(tmp_path, content))
    assert len(reqs) == 2
    names = {r.package for r in reqs}
    assert names == {"serde", "tokio"}
    assert all(r.ecosystem == Ecosystem.CARGO for r in reqs)


def test_cargo_toml_dev_dependencies(tmp_path: Path) -> None:
    content = '[dev-dependencies]\npretty_assertions = "1.0"\n'
    reqs = parse_cargo_toml(_cargo_toml(tmp_path, content))
    assert len(reqs) == 1
    assert reqs[0].package == "pretty_assertions"


def test_cargo_toml_pinned_version(tmp_path: Path) -> None:
    content = '[dependencies]\nserde = "1.0.193"\n'
    reqs = parse_cargo_toml(_cargo_toml(tmp_path, content))
    assert reqs[0].version == "1.0.193"


def test_cargo_toml_caret_version_stripped(tmp_path: Path) -> None:
    content = '[dependencies]\nserde = "^1.0"\n'
    reqs = parse_cargo_toml(_cargo_toml(tmp_path, content))
    assert reqs[0].version == "1.0"


def test_cargo_toml_table_dependency(tmp_path: Path) -> None:
    content = '[dependencies]\ntokio = { version = "1.28.0", features = ["full"] }\n'
    reqs = parse_cargo_toml(_cargo_toml(tmp_path, content))
    assert reqs[0].package == "tokio"
    assert reqs[0].version == "1.28.0"


def test_cargo_toml_git_dependency_no_version(tmp_path: Path) -> None:
    content = '[dependencies]\nmycrate = { git = "https://github.com/example/mycrate" }\n'
    reqs = parse_cargo_toml(_cargo_toml(tmp_path, content))
    assert reqs[0].package == "mycrate"
    assert reqs[0].version is None


def test_cargo_toml_empty(tmp_path: Path) -> None:
    content = '[package]\nname = "myapp"\nversion = "0.1.0"\n'
    reqs = parse_cargo_toml(_cargo_toml(tmp_path, content))
    assert reqs == []


# ── parse_package_lock_json ───────────────────────────────────────────────────


def _lock_json(tmp_path: Path, data: dict) -> Path:  # type: ignore[type-arg]
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(data))
    return p


def test_package_lock_json_v2_packages(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "root", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    }
    reqs = parse_package_lock_json(_lock_json(tmp_path, data))
    assert len(reqs) == 2
    names = {r.package for r in reqs}
    assert names == {"express", "lodash"}
    assert all(r.ecosystem == Ecosystem.NPM for r in reqs)


def test_package_lock_json_v2_version_extracted(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 2,
        "packages": {"node_modules/express": {"version": "4.18.2"}},
    }
    reqs = parse_package_lock_json(_lock_json(tmp_path, data))
    assert reqs[0].version == "4.18.2"


def test_package_lock_json_v1_dependencies(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.18.2", "resolved": "..."},
            "lodash": {"version": "4.17.21"},
        },
    }
    reqs = parse_package_lock_json(_lock_json(tmp_path, data))
    assert len(reqs) == 2
    names = {r.package for r in reqs}
    assert names == {"express", "lodash"}


def test_package_lock_json_skips_root_entry(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "myapp", "version": "1.0.0"},
            "node_modules/react": {"version": "18.2.0"},
        },
    }
    reqs = parse_package_lock_json(_lock_json(tmp_path, data))
    assert len(reqs) == 1
    assert reqs[0].package == "react"


def test_package_lock_json_scoped_package(tmp_path: Path) -> None:
    data = {
        "lockfileVersion": 2,
        "packages": {"node_modules/@scope/pkg": {"version": "1.0.0"}},
    }
    reqs = parse_package_lock_json(_lock_json(tmp_path, data))
    assert len(reqs) == 1
    assert reqs[0].package == "@scope/pkg"


def test_package_lock_json_empty(tmp_path: Path) -> None:
    data = {"lockfileVersion": 2, "packages": {}}
    reqs = parse_package_lock_json(_lock_json(tmp_path, data))
    assert reqs == []


# ── parse_manifest (auto-detect) ─────────────────────────────────────────────


def test_parse_manifest_requirements_txt(tmp_path: Path) -> None:
    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.31.0\n")
    reqs = parse_manifest(p)
    assert len(reqs) == 1
    assert reqs[0].ecosystem == Ecosystem.PYPI


def test_parse_manifest_package_json(tmp_path: Path) -> None:
    p = tmp_path / "package.json"
    p.write_text(json.dumps({"dependencies": {"express": "^4.18.0"}}))
    reqs = parse_manifest(p)
    assert len(reqs) == 1
    assert reqs[0].ecosystem == Ecosystem.NPM


def test_parse_manifest_cargo_toml(tmp_path: Path) -> None:
    p = tmp_path / "Cargo.toml"
    p.write_text('[dependencies]\nserde = "1.0"\n')
    reqs = parse_manifest(p)
    assert len(reqs) == 1
    assert reqs[0].ecosystem == Ecosystem.CARGO


def test_parse_manifest_unknown_raises(tmp_path: Path) -> None:
    p = tmp_path / "go.sum"
    p.write_text("")
    with pytest.raises(ValueError):
        parse_manifest(p)
