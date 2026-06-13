"""Unit tests for config loading and priority resolution."""
import textwrap
from pathlib import Path

from agentshield.core.config import Config, SeverityPolicy
from agentshield.core.models import Ecosystem, ResponseMode, Severity

# ── Default config ─────────────────────────────────────────────────────────────

def test_default_config_has_sane_defaults():
    cfg = Config()
    assert cfg.defaults.critical == ResponseMode.BLOCK
    assert cfg.defaults.high == ResponseMode.WARN_CONFIRM
    assert cfg.defaults.medium == ResponseMode.ASYNC_REPORT
    assert cfg.defaults.low == ResponseMode.IGNORE
    assert cfg.defaults.info == ResponseMode.IGNORE


def test_empty_allowlist_denylist():
    cfg = Config()
    assert cfg.allowlist == []
    assert cfg.denylist == []


# ── TOML loading ───────────────────────────────────────────────────────────────

def test_load_missing_path_returns_default(tmp_path: Path):
    cfg = Config.load(tmp_path / "nonexistent.toml")
    assert cfg.defaults.critical == ResponseMode.BLOCK


def test_load_full_config_from_toml(tmp_path: Path):
    toml_content = textwrap.dedent("""
        [defaults]
        critical = "block"
        high     = "block"
        medium   = "warn_confirm"
        low      = "ignore"
        info     = "ignore"

        [ecosystems.pypi]
        critical = "block"
        high     = "block"

        [rules."T1.2"]
        mode = "block"

        [allowlist]
        packages = ["numpy", "requests"]

        [denylist]
        packages = ["evil-package"]

        [cache]
        ttl_hours = 48
    """)
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)

    cfg = Config.load(config_file)

    assert cfg.defaults.high == ResponseMode.BLOCK
    assert cfg.defaults.medium == ResponseMode.WARN_CONFIRM
    assert "numpy" in cfg.allowlist
    assert "requests" in cfg.allowlist
    assert "evil-package" in cfg.denylist
    assert cfg.cache.ttl_hours == 48


def test_toml_allowlist_as_table(tmp_path: Path):
    """Verify that [allowlist] packages = [...] TOML table structure loads correctly."""
    toml_content = textwrap.dedent("""
        [allowlist]
        packages = ["numpy", "scipy"]
    """)
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)

    cfg = Config.load(config_file)
    assert cfg.allowlist == ["numpy", "scipy"]


def test_toml_denylist_as_table(tmp_path: Path):
    toml_content = textwrap.dedent("""
        [denylist]
        packages = ["bad-pkg"]
    """)
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)

    cfg = Config.load(config_file)
    assert cfg.denylist == ["bad-pkg"]


def test_cache_db_path_expansion(tmp_path: Path):
    toml_content = '[cache]\ndb_path = "~/.agentshield/custom.db"\n'
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml_content)

    cfg = Config.load(config_file)
    assert not str(cfg.cache.db_path).startswith("~")


# ── Priority resolution ───────────────────────────────────────────────────────

def test_global_default_used_when_no_override():
    cfg = Config()
    mode = cfg.response_mode_for("SOME-RULE", Severity.MEDIUM)
    assert mode == ResponseMode.ASYNC_REPORT


def test_rule_override_takes_highest_priority():
    cfg = Config.model_validate({
        "rules": {"T1.2": {"mode": "block"}},
        "defaults": {"high": "warn_confirm"},
    })
    mode = cfg.response_mode_for("T1.2", Severity.HIGH)
    assert mode == ResponseMode.BLOCK


def test_ecosystem_override_between_rule_and_default():
    cfg = Config.model_validate({
        "ecosystems": {"pypi": {"high": "block"}},
        "defaults": {"high": "warn_confirm"},
    })
    # With ecosystem override
    mode = cfg.response_mode_for("SOME-RULE", Severity.HIGH, Ecosystem.PYPI)
    assert mode == ResponseMode.BLOCK

    # Without ecosystem — falls back to global default
    mode_no_eco = cfg.response_mode_for("SOME-RULE", Severity.HIGH)
    assert mode_no_eco == ResponseMode.WARN_CONFIRM


def test_rule_overrides_ecosystem():
    cfg = Config.model_validate({
        "rules": {"T1.1": {"mode": "block"}},
        "ecosystems": {"pypi": {"critical": "warn_confirm"}},
    })
    # Rule takes priority over ecosystem
    mode = cfg.response_mode_for("T1.1", Severity.CRITICAL, Ecosystem.PYPI)
    assert mode == ResponseMode.BLOCK


def test_severity_policy_for_each_level():
    policy = SeverityPolicy(
        critical=ResponseMode.BLOCK,
        high=ResponseMode.WARN_CONFIRM,
        medium=ResponseMode.ASYNC_REPORT,
        low=ResponseMode.IGNORE,
        info=ResponseMode.IGNORE,
    )
    assert policy.for_severity(Severity.CRITICAL) == ResponseMode.BLOCK
    assert policy.for_severity(Severity.HIGH) == ResponseMode.WARN_CONFIRM
    assert policy.for_severity(Severity.MEDIUM) == ResponseMode.ASYNC_REPORT
    assert policy.for_severity(Severity.LOW) == ResponseMode.IGNORE
    assert policy.for_severity(Severity.INFO) == ResponseMode.IGNORE
    assert policy.for_severity(Severity.NONE) == ResponseMode.IGNORE
