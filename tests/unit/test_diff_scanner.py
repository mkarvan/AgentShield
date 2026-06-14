"""Unit tests for analyzers/diff_scanner.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentshield.analyzers.diff_scanner import (
    DiffScanResult,
    PackageDelta,
    compute_delta,
    run_diff_scan,
)
from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    ScanRequest,
    ScanResult,
    Severity,
)


# ── helpers ───────────────────────────────────────────────────────────────────


def _req(name: str, version: str | None = None, eco: Ecosystem = Ecosystem.PYPI) -> ScanRequest:
    return ScanRequest(package=name, version=version, ecosystem=eco)


def _allow_result(name: str, version: str | None = None) -> ScanResult:
    req = _req(name, version)
    return ScanResult(
        request=req,
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="ok"),
    )


def _block_result(name: str, version: str | None = None) -> ScanResult:
    req = _req(name, version)
    return ScanResult(
        request=req,
        findings=[],
        max_severity=Severity.HIGH,
        decision=Decision(action=DecisionAction.BLOCK, reason="blocked"),
    )


# ── compute_delta ─────────────────────────────────────────────────────────────


def test_compute_delta_no_changes() -> None:
    old = [_req("requests", "2.28.0"), _req("flask", "2.0.0")]
    new = [_req("requests", "2.28.0"), _req("flask", "2.0.0")]
    deltas = compute_delta(old, new)
    changes = {d.package: d.change for d in deltas}
    assert changes == {"requests": "unchanged", "flask": "unchanged"}


def test_compute_delta_added() -> None:
    old = [_req("requests", "2.28.0")]
    new = [_req("requests", "2.28.0"), _req("flask", "2.0.0")]
    deltas = compute_delta(old, new)
    added = [d for d in deltas if d.change == "added"]
    assert len(added) == 1
    assert added[0].package == "flask"


def test_compute_delta_removed() -> None:
    old = [_req("requests", "2.28.0"), _req("flask", "2.0.0")]
    new = [_req("requests", "2.28.0")]
    deltas = compute_delta(old, new)
    removed = [d for d in deltas if d.change == "removed"]
    assert len(removed) == 1
    assert removed[0].package == "flask"


def test_compute_delta_upgraded() -> None:
    old = [_req("requests", "2.28.0")]
    new = [_req("requests", "2.29.0")]
    deltas = compute_delta(old, new)
    assert len(deltas) == 1
    assert deltas[0].change == "upgraded"
    assert deltas[0].old_version == "2.28.0"
    assert deltas[0].version == "2.29.0"


def test_compute_delta_version_none_to_pinned() -> None:
    old = [_req("requests", None)]
    new = [_req("requests", "2.29.0")]
    deltas = compute_delta(old, new)
    assert deltas[0].change == "upgraded"


def test_compute_delta_case_insensitive_key() -> None:
    old = [_req("Requests", "2.28.0")]
    new = [_req("requests", "2.28.0")]
    deltas = compute_delta(old, new)
    assert all(d.change == "unchanged" for d in deltas)


def test_compute_delta_empty_old() -> None:
    new = [_req("flask", "2.0.0"), _req("requests", "2.28.0")]
    deltas = compute_delta([], new)
    assert all(d.change == "added" for d in deltas)
    assert len(deltas) == 2


def test_compute_delta_empty_new() -> None:
    old = [_req("flask", "2.0.0")]
    deltas = compute_delta(old, [])
    assert all(d.change == "removed" for d in deltas)


def test_compute_delta_mixed_ecosystems_treated_separately() -> None:
    old = [_req("lodash", "4.17.21", Ecosystem.NPM)]
    new = [_req("lodash", "4.17.21", Ecosystem.PYPI)]
    deltas = compute_delta(old, new)
    changes = {d.change for d in deltas}
    assert "added" in changes
    assert "removed" in changes


# ── DiffScanResult properties ─────────────────────────────────────────────────


def test_diff_result_total_scanned() -> None:
    result = DiffScanResult(
        old_path="old.txt",
        new_path="new.txt",
        added_results=[_allow_result("a"), _allow_result("b")],
        upgraded_results=[_allow_result("c")],
        removed=[],
        unchanged=[],
    )
    assert result.total_scanned == 3


def test_diff_result_blocked_count() -> None:
    result = DiffScanResult(
        old_path="old.txt",
        new_path="new.txt",
        added_results=[_block_result("evil")],
        upgraded_results=[_allow_result("ok")],
        removed=[],
        unchanged=[],
    )
    assert result.blocked == 1
    assert result.warned == 0


def test_diff_result_warned_count() -> None:
    req = _req("pkg")
    warn = ScanResult(
        request=req,
        findings=[],
        max_severity=Severity.MEDIUM,
        decision=Decision(action=DecisionAction.NEEDS_CONFIRMATION, reason="warn"),
    )
    result = DiffScanResult(
        old_path="old.txt",
        new_path="new.txt",
        added_results=[warn],
        upgraded_results=[],
        removed=[],
        unchanged=[],
    )
    assert result.warned == 1


# ── run_diff_scan ─────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_old(tmp_path: Path) -> Path:
    f = tmp_path / "old_requirements.txt"
    f.write_text("requests==2.28.0\nflask==2.0.0\n")
    return f


@pytest.fixture
def tmp_new(tmp_path: Path) -> Path:
    f = tmp_path / "new_requirements.txt"
    f.write_text("requests==2.29.0\nnumpy==1.24.0\n")
    return f


async def test_run_diff_scan_routes_correctly(tmp_old: Path, tmp_new: Path) -> None:
    shield = MagicMock()
    shield.ascan = AsyncMock(return_value=_allow_result("requests", "2.29.0"))

    result = await run_diff_scan(shield, tmp_old, tmp_new)

    # requests: upgraded; numpy: added; flask: removed
    assert result.total_scanned >= 1
    assert len(result.removed) == 1
    assert result.removed[0].package == "flask"


async def test_run_diff_scan_block_propagates(tmp_old: Path, tmp_new: Path) -> None:
    shield = MagicMock()
    shield.ascan = AsyncMock(return_value=_block_result("evil"))

    result = await run_diff_scan(shield, tmp_old, tmp_new)

    assert result.aggregate_decision.action == DecisionAction.BLOCK


async def test_run_diff_scan_all_allow(tmp_old: Path, tmp_new: Path) -> None:
    shield = MagicMock()
    shield.ascan = AsyncMock(return_value=_allow_result("pkg"))

    result = await run_diff_scan(shield, tmp_old, tmp_new)

    assert result.aggregate_decision.action == DecisionAction.ALLOW


async def test_run_diff_scan_no_changes(tmp_path: Path) -> None:
    same = tmp_path / "same.txt"
    same.write_text("requests==2.28.0\n")
    shield = MagicMock()
    shield.ascan = AsyncMock()

    result = await run_diff_scan(shield, same, same)

    assert result.total_scanned == 0
    assert result.aggregate_decision.action == DecisionAction.ALLOW
    shield.ascan.assert_not_called()
