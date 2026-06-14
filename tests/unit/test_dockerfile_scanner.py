"""Unit tests for analyzers/dockerfile_scanner.py."""

from __future__ import annotations

from pathlib import Path

from agentshield.analyzers.dockerfile_scanner import _exec_form_to_shell, parse_dockerfile
from agentshield.core.models import Ecosystem

# ── helpers ───────────────────────────────────────────────────────────────────


def _write_dockerfile(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "Dockerfile"
    p.write_text(content)
    return p


# ── _exec_form_to_shell ───────────────────────────────────────────────────────


def test_exec_form_pip() -> None:
    result = _exec_form_to_shell('["pip", "install", "requests"]')
    assert result == "pip install requests"


def test_exec_form_invalid_json() -> None:
    result = _exec_form_to_shell("not json")
    assert result == "not json"


def test_exec_form_non_list() -> None:
    result = _exec_form_to_shell('{"key": "val"}')
    assert result == '{"key": "val"}'


# ── parse_dockerfile — pip ────────────────────────────────────────────────────


def test_simple_pip_install(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "FROM python:3.11\nRUN pip install requests\n")
    reqs = parse_dockerfile(p)
    pkgs = [r.package for r in reqs]
    assert "requests" in pkgs
    assert all(r.ecosystem == Ecosystem.PYPI for r in reqs)


def test_pip_install_multiple_packages(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "FROM python:3.11\nRUN pip install flask requests numpy\n")
    reqs = parse_dockerfile(p)
    pkgs = {r.package for r in reqs}
    assert pkgs == {"flask", "requests", "numpy"}


def test_pip3_install(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "RUN pip3 install boto3\n")
    reqs = parse_dockerfile(p)
    assert any(r.package == "boto3" for r in reqs)


def test_python_m_pip_install(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "RUN python -m pip install pydantic\n")
    reqs = parse_dockerfile(p)
    assert any(r.package == "pydantic" for r in reqs)


# ── parse_dockerfile — npm ────────────────────────────────────────────────────


def test_npm_install(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "FROM node:18\nRUN npm install lodash express\n")
    reqs = parse_dockerfile(p)
    pkgs = {r.package for r in reqs}
    assert "lodash" in pkgs
    assert "express" in pkgs
    assert all(r.ecosystem == Ecosystem.NPM for r in reqs)


def test_yarn_add(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "RUN yarn add react react-dom\n")
    reqs = parse_dockerfile(p)
    pkgs = {r.package for r in reqs}
    assert "react" in pkgs
    assert "react-dom" in pkgs


# ── parse_dockerfile — cargo ──────────────────────────────────────────────────


def test_cargo_add(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "FROM rust:1.75\nRUN cargo add serde tokio\n")
    reqs = parse_dockerfile(p)
    pkgs = {r.package for r in reqs}
    assert "serde" in pkgs
    assert all(r.ecosystem == Ecosystem.CARGO for r in reqs)


def test_cargo_install(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "RUN cargo install ripgrep\n")
    reqs = parse_dockerfile(p)
    assert any(r.package == "ripgrep" for r in reqs)


# ── multiline and line continuation ──────────────────────────────────────────


def test_line_continuation(tmp_path: Path) -> None:
    content = "RUN pip install \\\n    requests \\\n    flask\n"
    p = _write_dockerfile(tmp_path, content)
    reqs = parse_dockerfile(p)
    pkgs = {r.package for r in reqs}
    assert "requests" in pkgs
    assert "flask" in pkgs


def test_multiple_run_commands(tmp_path: Path) -> None:
    content = (
        "FROM python:3.11\nRUN pip install requests\nRUN npm install lodash\nRUN cargo add serde\n"
    )
    p = _write_dockerfile(tmp_path, content)
    reqs = parse_dockerfile(p)
    ecosystems = {r.ecosystem for r in reqs}
    assert Ecosystem.PYPI in ecosystems
    assert Ecosystem.NPM in ecosystems
    assert Ecosystem.CARGO in ecosystems


# ── deduplication ─────────────────────────────────────────────────────────────


def test_deduplication(tmp_path: Path) -> None:
    content = "RUN pip install requests\nRUN pip install requests\n"
    p = _write_dockerfile(tmp_path, content)
    reqs = parse_dockerfile(p)
    pkg_names = [r.package for r in reqs if r.package == "requests"]
    assert len(pkg_names) == 1


# ── exec form ─────────────────────────────────────────────────────────────────


def test_exec_form_run(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, 'RUN ["pip", "install", "requests", "flask"]\n')
    reqs = parse_dockerfile(p)
    pkgs = {r.package for r in reqs}
    assert "requests" in pkgs
    assert "flask" in pkgs


# ── empty / no installs ───────────────────────────────────────────────────────


def test_no_install_commands(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, 'FROM python:3.11\nRUN echo hello\nCMD ["python", "app.py"]\n')
    reqs = parse_dockerfile(p)
    assert reqs == []


def test_empty_dockerfile(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "")
    assert parse_dockerfile(p) == []


# ── source field ─────────────────────────────────────────────────────────────


def test_source_set_to_dockerfile(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "RUN pip install requests\n")
    reqs = parse_dockerfile(p)
    assert all(r.source == "dockerfile" for r in reqs)


# ── skip flags / options ──────────────────────────────────────────────────────


def test_pip_flags_skipped(tmp_path: Path) -> None:
    p = _write_dockerfile(tmp_path, "RUN pip install -r requirements.txt requests\n")
    reqs = parse_dockerfile(p)
    pkgs = {r.package for r in reqs}
    # -r takes next token as arg; requests should be detected
    assert "requests" in pkgs
    # requirements.txt should not be treated as a package
    assert "requirements.txt" not in pkgs
