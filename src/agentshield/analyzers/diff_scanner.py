"""Diff scan mode — scan only the package delta between two manifest snapshots.

Usage:
    agentshield diff-scan old-requirements.txt new-requirements.txt

Delta categories
  added     — package present in new but not old (fully scanned)
  upgraded  — version changed between old and new (scanned at new version)
  removed   — package removed from new manifest (listed, not scanned)
  unchanged — same package + version in both (skipped)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    ScanRequest,
    ScanResult,
)

logger = logging.getLogger(__name__)

_SCAN_CONCURRENCY = 10


@dataclass
class PackageDelta:
    package: str
    version: str | None
    ecosystem: Ecosystem
    change: Literal["added", "upgraded", "removed", "unchanged"]
    old_version: str | None = None


@dataclass
class DiffScanResult:
    old_path: str
    new_path: str
    added_results: list[ScanResult] = field(default_factory=list)
    upgraded_results: list[ScanResult] = field(default_factory=list)
    removed: list[PackageDelta] = field(default_factory=list)
    unchanged: list[PackageDelta] = field(default_factory=list)
    aggregate_decision: Decision = field(
        default_factory=lambda: Decision(action=DecisionAction.ALLOW, reason="No changes")
    )

    @property
    def total_scanned(self) -> int:
        return len(self.added_results) + len(self.upgraded_results)

    @property
    def blocked(self) -> int:
        return sum(
            1
            for r in self.added_results + self.upgraded_results
            if r.decision.action == DecisionAction.BLOCK
        )

    @property
    def warned(self) -> int:
        return sum(
            1
            for r in self.added_results + self.upgraded_results
            if r.decision.action in (DecisionAction.NEEDS_CONFIRMATION, DecisionAction.LOG_ASYNC)
        )


def _pkg_key(req: ScanRequest) -> str:
    """Canonical key: lowercase name + ecosystem."""
    return f"{req.package.lower()}:{req.ecosystem.value}"


def compute_delta(
    old_requests: list[ScanRequest],
    new_requests: list[ScanRequest],
) -> list[PackageDelta]:
    """Compare two package lists and return per-package change annotations."""
    old_map = {_pkg_key(r): r for r in old_requests}
    new_map = {_pkg_key(r): r for r in new_requests}

    deltas: list[PackageDelta] = []

    for key, new_req in new_map.items():
        if key not in old_map:
            deltas.append(
                PackageDelta(
                    package=new_req.package,
                    version=new_req.version,
                    ecosystem=new_req.ecosystem,
                    change="added",
                )
            )
        else:
            old_req = old_map[key]
            if old_req.version != new_req.version:
                deltas.append(
                    PackageDelta(
                        package=new_req.package,
                        version=new_req.version,
                        ecosystem=new_req.ecosystem,
                        change="upgraded",
                        old_version=old_req.version,
                    )
                )
            else:
                deltas.append(
                    PackageDelta(
                        package=new_req.package,
                        version=new_req.version,
                        ecosystem=new_req.ecosystem,
                        change="unchanged",
                    )
                )

    for key, old_req in old_map.items():
        if key not in new_map:
            deltas.append(
                PackageDelta(
                    package=old_req.package,
                    version=old_req.version,
                    ecosystem=old_req.ecosystem,
                    change="removed",
                )
            )

    return deltas


async def run_diff_scan(
    shield: object,
    old_path: Path,
    new_path: Path,
) -> DiffScanResult:
    """Parse both manifests, compute the delta, and scan added/upgraded packages only."""
    from agentshield.core.manifest import parse_manifest
    from agentshield.core.scanner import AgentShield

    real_shield: AgentShield = shield  # type: ignore[assignment]

    old_requests = parse_manifest(old_path)
    new_requests = parse_manifest(new_path)
    deltas = compute_delta(old_requests, new_requests)

    to_scan = [d for d in deltas if d.change in ("added", "upgraded")]
    removed = [d for d in deltas if d.change == "removed"]
    unchanged = [d for d in deltas if d.change == "unchanged"]

    sem = asyncio.Semaphore(_SCAN_CONCURRENCY)

    async def _scan_one(delta: PackageDelta) -> tuple[PackageDelta, ScanResult | Exception]:
        async with sem:
            req = ScanRequest(
                package=delta.package,
                version=delta.version,
                ecosystem=delta.ecosystem,
                source="diff-scan",
            )
            try:
                result = await real_shield.ascan(req)
                return delta, result
            except Exception as exc:
                logger.warning("Diff scan failed for %s: %s", delta.package, exc)
                return delta, exc

    raw = await asyncio.gather(*[_scan_one(d) for d in to_scan])

    added_results: list[ScanResult] = []
    upgraded_results: list[ScanResult] = []
    for delta, outcome in raw:
        if not isinstance(outcome, ScanResult):
            continue
        if delta.change == "added":
            added_results.append(outcome)
        else:
            upgraded_results.append(outcome)

    all_results = added_results + upgraded_results
    n_blocked = sum(1 for r in all_results if r.decision.action == DecisionAction.BLOCK)
    n_warned = sum(
        1
        for r in all_results
        if r.decision.action in (DecisionAction.NEEDS_CONFIRMATION, DecisionAction.LOG_ASYNC)
    )

    if n_blocked:
        agg_action = DecisionAction.BLOCK
        agg_reason = f"{n_blocked} package(s) blocked"
    elif n_warned:
        agg_action = DecisionAction.NEEDS_CONFIRMATION
        agg_reason = f"{n_warned} package(s) require review"
    elif all_results:
        agg_action = DecisionAction.ALLOW
        agg_reason = f"All {len(all_results)} changed package(s) passed"
    else:
        agg_action = DecisionAction.ALLOW
        agg_reason = "No package changes detected"

    return DiffScanResult(
        old_path=str(old_path),
        new_path=str(new_path),
        added_results=added_results,
        upgraded_results=upgraded_results,
        removed=removed,
        unchanged=unchanged,
        aggregate_decision=Decision(action=agg_action, reason=agg_reason),
    )
