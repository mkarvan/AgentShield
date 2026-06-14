"""Shared fixtures and marker registration for e2e tests."""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from agentshield.core.config import Config


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "network: marks tests that make real network calls (skip with -m 'not network')",
    )
    config.addinivalue_line(
        "markers",
        "slow: marks tests that are slow (skip with -m 'not slow')",
    )


# ── manifest content ──────────────────────────────────────────────────────────

_REQUIREMENTS_TXT = """\
requests==2.28.0
flask==2.3.0
numpy==1.24.0
# a comment line
"""

_OLD_REQUIREMENTS_TXT = """\
requests==2.27.0
numpy==1.23.0
"""

_NEW_REQUIREMENTS_TXT = """\
requests==2.28.0
numpy==1.24.0
flask==2.3.0
"""

_PACKAGE_JSON = """\
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "^4.17.21",
    "express": "^4.18.0"
  }
}
"""

_CARGO_TOML = """\
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"""

_DOCKERFILE = """\
FROM python:3.11-slim

WORKDIR /app

RUN pip install requests flask

RUN npm install lodash
"""

# ── path fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def sample_requirements_txt(tmp_path: Path) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text(_REQUIREMENTS_TXT)
    return p


@pytest.fixture
def sample_old_requirements_txt(tmp_path: Path) -> Path:
    p = tmp_path / "old_requirements.txt"
    p.write_text(_OLD_REQUIREMENTS_TXT)
    return p


@pytest.fixture
def sample_new_requirements_txt(tmp_path: Path) -> Path:
    p = tmp_path / "new_requirements.txt"
    p.write_text(_NEW_REQUIREMENTS_TXT)
    return p


@pytest.fixture
def sample_package_json(tmp_path: Path) -> Path:
    p = tmp_path / "package.json"
    p.write_text(_PACKAGE_JSON)
    return p


@pytest.fixture
def sample_cargo_toml(tmp_path: Path) -> Path:
    p = tmp_path / "Cargo.toml"
    p.write_text(_CARGO_TOML)
    return p


@pytest.fixture
def sample_dockerfile(tmp_path: Path) -> Path:
    p = tmp_path / "Dockerfile"
    p.write_text(_DOCKERFILE)
    return p


# ── config / shield fixtures ──────────────────────────────────────────────────


@pytest.fixture
def test_config(tmp_path: Path) -> Config:
    """Offline config with an isolated test DB."""
    return Config.model_validate(
        {
            "cache": {"db_path": str(tmp_path / "e2e_test.db")},
            "offline": True,
        }
    )


@pytest.fixture
def shield(test_config: Config) -> object:
    from agentshield.core.scanner import AgentShield

    return AgentShield(config=test_config)


@pytest.fixture
def denylist_config(tmp_path: Path) -> Config:
    """Config with common test packages on denylist (blocks without network)."""
    return Config.model_validate(
        {
            "denylist": ["evil-pypi-pkg", "evil-npm-pkg", "evil-crate"],
            "cache": {"db_path": str(tmp_path / "denylist_test.db")},
        }
    )


@pytest.fixture
def allowlist_config(tmp_path: Path) -> Config:
    """Config with common safe packages on allowlist (allows without network)."""
    return Config.model_validate(
        {
            "allowlist": ["requests", "flask", "numpy", "lodash", "express", "serde", "tokio"],
            "cache": {"db_path": str(tmp_path / "allowlist_test.db")},
        }
    )


@pytest.fixture
def cli_config_file(tmp_path: Path) -> Path:
    """Write a minimal TOML config file and return its path (for --config flag)."""
    cfg = tmp_path / "test_config.toml"
    db_path = tmp_path / "cli_test.db"
    cfg.write_text(
        f'[cache]\ndb_path = "{db_path}"\nttl_hours = 24\n\n'
        '[denylist]\npackages = ["evil-pypi-pkg", "evil-npm-pkg", "evil-crate"]\n\n'
        '[allowlist]\npackages = ["requests", "flask", "numpy", "lodash", "serde", "tokio"]\n'
    )
    return cfg


@pytest.fixture
def short_sock_dir() -> Generator[Path, None, None]:
    """Create a temp dir with a short path for Unix socket paths.

    macOS limits AF_UNIX socket paths to 104 characters (including null
    terminator), but pytest's tmp_path can exceed that.  This fixture always
    produces a short path that's safely under the limit.
    """
    d = tempfile.mkdtemp(prefix="as_", dir="/tmp")
    try:
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)
