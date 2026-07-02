"""Unit tests for Phase 2 static analysis components.

All tests operate on local fixture packages — no network calls.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentshield.analyzers.setup_py_inspector import inspect_package_directory
from agentshield.core.models import Ecosystem, ScanRequest, Severity

FIXTURES = Path(__file__).parent.parent / "fixtures" / "packages"


def _req(package: str = "test-pkg") -> ScanRequest:
    return ScanRequest(package=package, ecosystem=Ecosystem.PYPI)


# ── setup_py_inspector: each fixture triggers its rule ───────────────────────


def test_shell_exec_fixture_fires_T3_1():
    findings = inspect_package_directory(FIXTURES / "shell_exec", _req())
    rule_ids = {f.rule_id for f in findings}
    assert "T3.1" in rule_ids, f"Expected T3.1 in {rule_ids}"


def test_network_at_install_fixture_fires_T3_2():
    findings = inspect_package_directory(FIXTURES / "network_at_install", _req())
    rule_ids = {f.rule_id for f in findings}
    assert "T3.2" in rule_ids, f"Expected T3.2 in {rule_ids}"


def test_filesystem_write_fixture_fires_T3_3():
    findings = inspect_package_directory(FIXTURES / "filesystem_write", _req())
    rule_ids = {f.rule_id for f in findings}
    assert "T3.3" in rule_ids, f"Expected T3.3 in {rule_ids}"


def test_obfuscated_payload_fixture_fires_T3_4():
    findings = inspect_package_directory(FIXTURES / "obfuscated_payload", _req())
    rule_ids = {f.rule_id for f in findings}
    assert "T3.4" in rule_ids, f"Expected T3.4 in {rule_ids}"


def test_cred_harvester_fixture_fires_T3_5():
    findings = inspect_package_directory(FIXTURES / "cred_harvester", _req())
    rule_ids = {f.rule_id for f in findings}
    assert "T3.5" in rule_ids, f"Expected T3.5 in {rule_ids}"


def test_cred_harvester_also_fires_T3_2():
    # cred_harvester also makes a network call — both rules should fire
    findings = inspect_package_directory(FIXTURES / "cred_harvester", _req())
    rule_ids = {f.rule_id for f in findings}
    assert "T3.2" in rule_ids, "cred_harvester network call should also trigger T3.2"


# ── No false positives on benign package ─────────────────────────────────────


def test_benign_package_no_findings():
    findings = inspect_package_directory(FIXTURES / "benign_package", _req())
    assert findings == [], f"Expected no findings for benign package, got: {findings}"


# ── Severity levels are correct ───────────────────────────────────────────────


def test_obfuscated_payload_severity_is_critical():
    findings = inspect_package_directory(FIXTURES / "obfuscated_payload", _req())
    t3_4 = [f for f in findings if f.rule_id == "T3.4"]
    assert t3_4, "T3.4 finding missing"
    assert t3_4[0].severity == Severity.CRITICAL


def test_cred_harvester_severity_is_critical():
    findings = inspect_package_directory(FIXTURES / "cred_harvester", _req())
    t3_5 = [f for f in findings if f.rule_id == "T3.5"]
    assert t3_5, "T3.5 finding missing"
    assert t3_5[0].severity == Severity.CRITICAL


def test_shell_exec_severity_is_high():
    findings = inspect_package_directory(FIXTURES / "shell_exec", _req())
    t3_1 = [f for f in findings if f.rule_id == "T3.1"]
    assert t3_1, "T3.1 finding missing"
    assert t3_1[0].severity == Severity.HIGH


def test_network_severity_is_high():
    findings = inspect_package_directory(FIXTURES / "network_at_install", _req())
    t3_2 = [f for f in findings if f.rule_id == "T3.2"]
    assert t3_2, "T3.2 finding missing"
    assert t3_2[0].severity == Severity.HIGH


# ── Source field ──────────────────────────────────────────────────────────────


def test_findings_source_is_setup_py_inspector():
    findings = inspect_package_directory(FIXTURES / "shell_exec", _req())
    for f in findings:
        assert f.source == "setup_py_inspector", (
            f"Expected source 'setup_py_inspector', got {f.source!r}"
        )


# ── Missing / empty directory ─────────────────────────────────────────────────


def test_empty_directory_no_crash(tmp_path: Path):
    findings = inspect_package_directory(tmp_path, _req())
    assert findings == []


def test_directory_with_no_setup_py(tmp_path: Path):
    (tmp_path / "mymodule.py").write_text("x = 1\n")
    findings = inspect_package_directory(tmp_path, _req())
    assert findings == []


# ── bandit_runner: availability check ────────────────────────────────────────


@pytest.mark.asyncio
async def test_bandit_runner_returns_list_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """bandit_runner should return [] gracefully when bandit is not on PATH."""
    import agentshield.analyzers.bandit_runner as br

    monkeypatch.setattr(br, "_bandit_available", lambda: None)
    result = await br.run_bandit(tmp_path, _req())
    assert result == []


@pytest.mark.asyncio
async def test_bandit_runner_returns_list_on_shell_exec(tmp_path: Path):
    """bandit_runner fires on subprocess usage in Python files."""
    from agentshield.analyzers.bandit_runner import _bandit_available, run_bandit

    if _bandit_available() is None:
        pytest.skip("bandit not installed")

    (tmp_path / "setup.py").write_text("import subprocess\nsubprocess.run(['id'])\n")
    findings = await run_bandit(tmp_path, _req())
    # bandit B404 (import_subprocess) or B603 (subprocess_without_shell_equals_true)
    assert any("T3.1" in f.rule_id or "bandit:" in f.rule_id for f in findings), (
        f"Expected subprocess finding, got: {findings}"
    )


# ── semgrep_runner: graceful degradation ─────────────────────────────────────


@pytest.mark.asyncio
async def test_semgrep_runner_returns_empty_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    import agentshield.analyzers.semgrep_runner as sr

    monkeypatch.setattr(sr, "_semgrep_available", lambda: None)
    result = await sr.run_semgrep(tmp_path, _req())
    assert result == []


# ── npm_audit_runner: graceful degradation ───────────────────────────────────


@pytest.mark.asyncio
async def test_npm_audit_runner_returns_empty_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    import agentshield.analyzers.npm_audit_runner as na

    monkeypatch.setattr(na, "_npm_available", lambda: None)
    result = await na.run_npm_audit(tmp_path, _req())
    assert result == []


@pytest.mark.asyncio
async def test_npm_audit_runner_skips_without_lockfile(tmp_path: Path):
    from agentshield.analyzers.npm_audit_runner import _npm_available, run_npm_audit

    if _npm_available() is None:
        pytest.skip("npm not installed")
    # No package.json in tmp_path — should return []
    result = await run_npm_audit(tmp_path, _req())
    assert result == []


# ── cargo_audit_runner: graceful degradation ─────────────────────────────────


@pytest.mark.asyncio
async def test_cargo_audit_runner_returns_empty_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    import agentshield.analyzers.cargo_audit_runner as ca

    monkeypatch.setattr(ca, "_cargo_audit_available", lambda: None)
    result = await ca.run_cargo_audit(tmp_path, _req())
    assert result == []


@pytest.mark.asyncio
async def test_cargo_audit_runner_skips_without_lockfile(tmp_path: Path):
    from agentshield.analyzers.cargo_audit_runner import _cargo_audit_available, run_cargo_audit

    if _cargo_audit_available() is None:
        pytest.skip("cargo not installed")
    # No Cargo.lock in tmp_path — should return []
    result = await run_cargo_audit(tmp_path, _req())
    assert result == []


# ── Scanner integration: --deep flag wiring ───────────────────────────────────


@pytest.mark.asyncio
async def test_deep_flag_false_skips_static_analysis(tmp_path: Path):
    """Without --deep, _run_deep_checks should never be called."""
    from unittest.mock import AsyncMock, patch

    from agentshield.core.config import Config
    from agentshield.core.models import Ecosystem, ScanRequest
    from agentshield.core.scanner import AgentShield

    cfg = Config.model_validate(
        {
            "cache": {"db_path": str(tmp_path / "cache.db")},
        }
    )
    shield = AgentShield(config=cfg)

    with (
        patch.object(shield, "_run_checks", new_callable=AsyncMock, return_value=[]),
        patch.object(shield, "_run_deep_checks", new_callable=AsyncMock) as mock_deep,
    ):
        await shield.ascan(ScanRequest(package="some-pkg", ecosystem=Ecosystem.PYPI, deep=False))
        mock_deep.assert_not_called()


@pytest.mark.asyncio
async def test_deep_flag_true_invokes_static_analysis(tmp_path: Path):
    """With --deep, _run_deep_checks is invoked (but may return [] if tools unavailable)."""
    from unittest.mock import AsyncMock, patch

    from agentshield.core.config import Config
    from agentshield.core.models import Ecosystem, ScanRequest
    from agentshield.core.scanner import AgentShield

    cfg = Config.model_validate(
        {
            "cache": {"db_path": str(tmp_path / "cache.db")},
        }
    )
    shield = AgentShield(config=cfg)

    with (
        patch.object(shield, "_run_checks", new_callable=AsyncMock, return_value=[]),
        patch.object(
            shield, "_run_deep_checks", new_callable=AsyncMock, return_value=[]
        ) as mock_deep,
    ):
        await shield.ascan(ScanRequest(package="some-pkg", ecosystem=Ecosystem.PYPI, deep=True))
        mock_deep.assert_called_once()


# ── Deep scan: unsupported ecosystems are explicit, not silent no-ops ──────────


def _shield(tmp_path: Path):
    from agentshield.core.config import Config
    from agentshield.core.scanner import AgentShield

    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})
    return AgentShield(config=cfg)


@pytest.mark.asyncio
@pytest.mark.parametrize("ecosystem", [Ecosystem.NPM, Ecosystem.CARGO])
async def test_deep_checks_unsupported_ecosystem_returns_info_finding(
    tmp_path: Path, ecosystem: Ecosystem
):
    """Deep scan for npm/cargo emits a clear INFO finding instead of a silent no-op."""
    shield = _shield(tmp_path)

    findings = await shield._run_deep_checks(
        ScanRequest(package="some-pkg", ecosystem=ecosystem, deep=True)
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "DEEP.UNSUPPORTED"
    assert f.severity == Severity.INFO
    assert f.source == "deep_scan"
    assert f.metadata["ecosystem"] == ecosystem.value
    assert ecosystem.value in f.title


@pytest.mark.asyncio
@pytest.mark.parametrize("ecosystem", [Ecosystem.NPM, Ecosystem.CARGO])
async def test_deep_checks_unsupported_ecosystem_skips_extraction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ecosystem: Ecosystem
):
    """npm/cargo deep scans must NOT attempt extraction (which only supports PyPI)."""
    import agentshield.analyzers.wheel_extractor as we

    def _boom(*args: object, **kwargs: object):
        raise AssertionError("extracted_package must not be called for non-PyPI ecosystems")

    monkeypatch.setattr(we, "extracted_package", _boom)

    shield = _shield(tmp_path)
    findings = await shield._run_deep_checks(
        ScanRequest(package="some-pkg", ecosystem=ecosystem, deep=True)
    )

    assert [f.rule_id for f in findings] == ["DEEP.UNSUPPORTED"]


@pytest.mark.asyncio
async def test_deep_checks_pypi_attempts_extraction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """PyPI deep scans still go through extracted_package and never emit DEEP.UNSUPPORTED."""
    import agentshield.analyzers.wheel_extractor as we
    from agentshield.analyzers.wheel_extractor import WheelExtractionError

    called = False

    def _fail(*args: object, **kwargs: object):
        nonlocal called
        called = True
        raise WheelExtractionError("no network in test")

    monkeypatch.setattr(we, "extracted_package", _fail)

    shield = _shield(tmp_path)
    findings = await shield._run_deep_checks(
        ScanRequest(package="some-pkg", ecosystem=Ecosystem.PYPI, deep=True)
    )

    assert called is True
    assert findings == []  # extraction failure is swallowed, no DEEP.UNSUPPORTED finding
    assert all(f.rule_id != "DEEP.UNSUPPORTED" for f in findings)


@pytest.mark.asyncio
async def test_deep_unsupported_finding_does_not_block(tmp_path: Path):
    """The INFO DEEP.UNSUPPORTED finding must not escalate the scan decision."""
    from unittest.mock import AsyncMock, patch

    from agentshield.core.config import Config
    from agentshield.core.models import DecisionAction
    from agentshield.core.scanner import AgentShield

    cfg = Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}, "offline": True})
    shield = AgentShield(config=cfg)

    with patch.object(shield, "_run_offline_checks", new_callable=AsyncMock, return_value=[]):
        result = await shield.ascan(
            ScanRequest(package="some-pkg", ecosystem=Ecosystem.NPM, deep=True)
        )

    assert "DEEP.UNSUPPORTED" in {f.rule_id for f in result.findings}
    assert result.decision.action == DecisionAction.ALLOW


# ── timed-out subprocesses are killed (regression) ─────────────────────────────


def test_bandit_timeout_kills_process(monkeypatch, tmp_path):
    """A bandit run that exceeds the timeout must be killed, not leaked."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    from agentshield.analyzers import bandit_runner
    from agentshield.core.models import Ecosystem, ScanRequest

    proc = MagicMock()
    proc.returncode = None
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
    proc.kill = MagicMock()
    proc.wait = AsyncMock()

    monkeypatch.setattr(bandit_runner, "_bandit_available", lambda: "/usr/bin/bandit")
    monkeypatch.setattr(
        bandit_runner.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)
    )

    req = ScanRequest(package="p", ecosystem=Ecosystem.PYPI)
    findings = asyncio.run(bandit_runner.run_bandit(tmp_path, req))
    assert findings == []
    proc.kill.assert_called_once()


def test_semgrep_timeout_kills_process(monkeypatch, tmp_path):
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    from agentshield.analyzers import semgrep_runner
    from agentshield.core.models import Ecosystem, ScanRequest

    proc = MagicMock()
    proc.returncode = None
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
    proc.kill = MagicMock()
    proc.wait = AsyncMock()

    monkeypatch.setattr(semgrep_runner, "_semgrep_available", lambda: "/usr/bin/semgrep")
    monkeypatch.setattr(
        semgrep_runner.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)
    )

    req = ScanRequest(package="p", ecosystem=Ecosystem.PYPI)
    findings = asyncio.run(semgrep_runner.run_semgrep(tmp_path, req))
    assert findings == []
    proc.kill.assert_called_once()
