"""Unit tests for AgentShield.scan_file() / ascan_file() and FileScanResult."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
import respx
from httpx import Response

from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    FileScanResult,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.core.scanner import AgentShield

OSV_URL = "https://api.osv.dev/v1/query"


def _make_cfg(tmp_path: Path) -> Config:
    return Config.model_validate({"cache": {"db_path": str(tmp_path / "cache.db")}})


def _allow_result(pkg: str) -> ScanResult:
    return ScanResult(
        request=ScanRequest(package=pkg, ecosystem=Ecosystem.PYPI),
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="ok"),
    )


def _block_result(pkg: str) -> ScanResult:
    from agentshield.core.models import Finding

    f = Finding(rule_id="T1.1", title="bad", severity=Severity.CRITICAL, source="test")
    return ScanResult(
        request=ScanRequest(package=pkg, ecosystem=Ecosystem.PYPI),
        findings=[f],
        max_severity=Severity.CRITICAL,
        decision=Decision(action=DecisionAction.BLOCK, reason="blocked"),
    )


# ── FileScanResult.from_results ───────────────────────────────────────────────


def test_file_scan_result_all_allow(tmp_path: Path) -> None:
    results = [_allow_result("a"), _allow_result("b")]
    fsr = FileScanResult.from_results(tmp_path / "requirements.txt", results)
    assert fsr.aggregate_decision.action == DecisionAction.ALLOW
    assert fsr.total_packages == 2
    assert fsr.blocked == 0
    assert fsr.allowed == 2


def test_file_scan_result_one_block(tmp_path: Path) -> None:
    results = [_allow_result("a"), _block_result("evil")]
    fsr = FileScanResult.from_results(tmp_path / "requirements.txt", results)
    assert fsr.aggregate_decision.action == DecisionAction.BLOCK
    assert fsr.blocked == 1
    assert fsr.allowed == 1


def test_file_scan_result_empty(tmp_path: Path) -> None:
    fsr = FileScanResult.from_results(tmp_path / "requirements.txt", [])
    assert fsr.aggregate_decision.action == DecisionAction.ALLOW
    assert fsr.total_packages == 0


def test_file_scan_result_total_findings(tmp_path: Path) -> None:
    from agentshield.core.models import Finding

    f = Finding(rule_id="X", title="t", severity=Severity.LOW, source="s")
    r = ScanResult(
        request=ScanRequest(package="pkg", ecosystem=Ecosystem.PYPI),
        findings=[f, f],
        max_severity=Severity.LOW,
        decision=Decision(action=DecisionAction.ALLOW, reason="ok"),
    )
    fsr = FileScanResult.from_results(tmp_path / "requirements.txt", [r])
    assert fsr.total_findings == 2


def test_file_scan_result_needs_confirmation(tmp_path: Path) -> None:
    r = ScanResult(
        request=ScanRequest(package="pkg", ecosystem=Ecosystem.PYPI),
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.NEEDS_CONFIRMATION, reason="check"),
    )
    fsr = FileScanResult.from_results(tmp_path / "requirements.txt", [r])
    assert fsr.aggregate_decision.action == DecisionAction.NEEDS_CONFIRMATION
    assert fsr.warned == 1


def test_file_scan_result_log_async_counts_as_warned(tmp_path: Path) -> None:
    r = ScanResult(
        request=ScanRequest(package="pkg", ecosystem=Ecosystem.PYPI),
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.LOG_ASYNC, reason="logged"),
    )
    fsr = FileScanResult.from_results(tmp_path / "requirements.txt", [r])
    assert fsr.warned == 1


# ── transitive results must drive the aggregate (regression) ──────────────────
# A clean package depending on a blocked one still installs the blocked code;
# aggregates/exit codes previously only looked at the package's own decision.


def _allow_with_blocked_dep(pkg: str, dep: str) -> ScanResult:
    clean = _allow_result(pkg)
    return clean.model_copy(update={"transitive_results": [_block_result(dep)]})


def test_effective_action_is_own_action_without_transitives() -> None:
    assert _allow_result("a").effective_action == DecisionAction.ALLOW
    assert _block_result("b").effective_action == DecisionAction.BLOCK


def test_effective_action_escalates_to_transitive_block() -> None:
    r = _allow_with_blocked_dep("clean-pkg", "evil-dep")
    assert r.decision.action == DecisionAction.ALLOW
    assert r.effective_action == DecisionAction.BLOCK


def test_effective_action_escalates_to_transitive_needs_confirmation() -> None:
    dep = _allow_result("dep").model_copy(
        update={"decision": Decision(action=DecisionAction.NEEDS_CONFIRMATION, reason="check")}
    )
    r = _allow_result("pkg").model_copy(update={"transitive_results": [dep]})
    assert r.effective_action == DecisionAction.NEEDS_CONFIRMATION


def test_file_scan_result_transitive_block_counts_as_blocked(tmp_path: Path) -> None:
    results = [_allow_result("a"), _allow_with_blocked_dep("clean-pkg", "evil-dep")]
    fsr = FileScanResult.from_results(tmp_path / "requirements.txt", results)
    assert fsr.aggregate_decision.action == DecisionAction.BLOCK
    assert fsr.blocked == 1
    assert fsr.allowed == 1


# ── ascan_file integration with mocked network ────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_ascan_file_requirements_txt_all_clean(tmp_path: Path) -> None:
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    cfg = _make_cfg(tmp_path)
    shield = AgentShield(config=cfg)

    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.31.0\nflask==2.3.0\n")

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan_file(p)

    assert result.total_packages == 2
    assert result.blocked == 0
    assert result.aggregate_decision.action in (DecisionAction.ALLOW, DecisionAction.LOG_ASYNC)


@pytest.mark.asyncio
@respx.mock
async def test_ascan_file_package_json_all_clean(tmp_path: Path) -> None:
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    cfg = _make_cfg(tmp_path)
    shield = AgentShield(config=cfg)

    p = tmp_path / "package.json"
    p.write_text(json.dumps({"dependencies": {"express": "^4.18.0"}}))

    with patch("agentshield.analyzers.typosquatting.TyposquattingChecker._load", return_value=[]):
        result = await shield.ascan_file(p)

    assert result.total_packages == 1
    assert result.results[0].request.ecosystem == Ecosystem.NPM


@pytest.mark.asyncio
@respx.mock
async def test_ascan_file_empty_manifest(tmp_path: Path) -> None:
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    cfg = _make_cfg(tmp_path)
    shield = AgentShield(config=cfg)

    p = tmp_path / "requirements.txt"
    p.write_text("# only comments\n")

    result = await shield.ascan_file(p)
    assert result.total_packages == 0
    assert result.aggregate_decision.action == DecisionAction.ALLOW


@pytest.mark.asyncio
async def test_ascan_file_unknown_format_raises(tmp_path: Path) -> None:
    cfg = _make_cfg(tmp_path)
    shield = AgentShield(config=cfg)
    p = tmp_path / "go.sum"
    p.write_text("")
    with pytest.raises(ValueError, match="Unrecognized manifest filename"):
        await shield.ascan_file(p)


def test_scan_file_sync_wrapper(tmp_path: Path) -> None:
    cfg = Config.model_validate(
        {
            "allowlist": ["requests"],
            "cache": {"db_path": str(tmp_path / "cache.db")},
        }
    )
    shield = AgentShield(config=cfg)
    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.31.0\n")
    result = shield.scan_file(p)
    assert result.total_packages == 1
    assert result.aggregate_decision.action == DecisionAction.ALLOW


# ── Performance: _max_severity O(1) ──────────────────────────────────────────


def test_max_severity_uses_rank_dict() -> None:
    """_SEVERITY_RANK is a dict; test that _max_severity still returns correct values."""
    from agentshield.core.models import Finding, Severity
    from agentshield.core.scanner import _max_severity

    findings = [
        Finding(rule_id="A", title="t", severity=Severity.LOW, source="s"),
        Finding(rule_id="B", title="t", severity=Severity.CRITICAL, source="s"),
        Finding(rule_id="C", title="t", severity=Severity.MEDIUM, source="s"),
    ]
    assert _max_severity(findings) == Severity.CRITICAL


def test_severity_rank_dict_order() -> None:
    from agentshield.core.scanner import _SEVERITY_RANK

    assert _SEVERITY_RANK["NONE"] < _SEVERITY_RANK["INFO"]
    assert _SEVERITY_RANK["INFO"] < _SEVERITY_RANK["LOW"]
    assert _SEVERITY_RANK["LOW"] < _SEVERITY_RANK["MEDIUM"]
    assert _SEVERITY_RANK["MEDIUM"] < _SEVERITY_RANK["HIGH"]
    assert _SEVERITY_RANK["HIGH"] < _SEVERITY_RANK["CRITICAL"]


def test_models_severity_rank_dict_order() -> None:
    from agentshield.core.models import _SEVERITY_RANK

    assert _SEVERITY_RANK["NONE"] < _SEVERITY_RANK["CRITICAL"]


# ── Performance: malicious_db curated normalization ───────────────────────────


def test_malicious_db_curated_lower_pre_normalized() -> None:
    from agentshield.databases.malicious_db import MaliciousDB

    db = MaliciousDB()
    db._curated = {"pypi": ["Evil-Package", "Another-BAD"]}
    db._curated_lower = None  # force lazy init

    lower = db._get_curated_lower()
    assert "evil-package" in lower.get("pypi", frozenset())
    assert "another-bad" in lower.get("pypi", frozenset())
    assert isinstance(lower.get("pypi"), frozenset)


@pytest.mark.asyncio
async def test_malicious_db_check_uses_frozenset() -> None:
    from agentshield.databases.malicious_db import MaliciousDB

    db = MaliciousDB()
    db._curated = {"pypi": ["Evil-Package"]}
    db._curated_lower = None

    req = ScanRequest(package="evil-package", ecosystem=Ecosystem.PYPI)
    findings = await db.check(req)
    assert len(findings) == 1
    assert findings[0].rule_id == "T1.1"


@pytest.mark.asyncio
async def test_malicious_db_get_curated_populates_lower() -> None:
    from agentshield.databases.malicious_db import MaliciousDB

    db = MaliciousDB()
    db._curated = None
    db._curated_lower = None

    with patch(
        "agentshield.databases.malicious_db._load_curated",
        return_value={"pypi": ["bad-pkg"]},
    ):
        curated = db._get_curated()
        assert "bad-pkg" in curated.get("pypi", [])
        lower = db._get_curated_lower()
        assert "bad-pkg" in lower.get("pypi", frozenset())
