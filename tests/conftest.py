import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "integration: marks tests that require network access (deselect with -m 'not integration')",
    )


@pytest.fixture(autouse=True)
def _agentshield_isolation(monkeypatch, tmp_path):
    from agentshield.core import config as _cfg

    monkeypatch.setattr(_cfg, "DEFAULT_CONFIG_PATH", tmp_path / "config.toml")
    monkeypatch.setattr(_cfg, "DEFAULT_DB_PATH", tmp_path / "agentshield.db")
    monkeypatch.setattr(_cfg, "DEFAULT_REPORT_DIR", tmp_path / "reports")

    from agentshield.server import ipc as _ipc

    monkeypatch.setattr(_ipc, "DEFAULT_SOCK_PATH", tmp_path / "agentshield.sock")
    monkeypatch.setattr(_ipc, "_DEFAULT_TOKEN_PATH", tmp_path / "ipc.token")
