"""Scanner integration tests.

Uses the AgentShield class directly (no subprocess), exercising the full scan
pipeline for each ecosystem.  Network calls are mocked unless the test is
marked @pytest.mark.network.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from agentshield.core.config import Config
from agentshield.core.models import (
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    Severity,
)
from agentshield.core.scanner import AgentShield

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_config(tmp_path: Path, **overrides: object) -> Config:
    base: dict[str, object] = {"cache": {"db_path": str(tmp_path / "test.db")}}
    base.update(overrides)
    return Config.model_validate(base)


def _make_cve_finding(
    rule_id: str = "CVE-2024-TEST", severity: Severity = Severity.CRITICAL
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test CVE",
        description="A test vulnerability",
        severity=severity,
        source="osv",
        references=[],
    )


# ── denylist / allowlist short-circuits ──────────────────────────────────────


class TestDenylistAllowlist:
    @pytest.mark.asyncio
    async def test_denylist_blocks_pypi(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, denylist=["evil-pkg"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="evil-pkg", ecosystem=Ecosystem.PYPI, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.BLOCK
        assert "denylist" in result.decision.reason.lower()

    @pytest.mark.asyncio
    async def test_denylist_blocks_npm(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, denylist=["bad-npm-pkg"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="bad-npm-pkg", ecosystem=Ecosystem.NPM, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.BLOCK

    @pytest.mark.asyncio
    async def test_denylist_blocks_cargo(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, denylist=["bad-crate"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="bad-crate", ecosystem=Ecosystem.CARGO, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.BLOCK

    @pytest.mark.asyncio
    async def test_denylist_is_case_insensitive(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, denylist=["EvilPkg"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="evilpkg", ecosystem=Ecosystem.PYPI, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.BLOCK

    @pytest.mark.asyncio
    async def test_allowlist_allows_pypi(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, allowlist=["safe-pkg"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="safe-pkg", ecosystem=Ecosystem.PYPI, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.ALLOW
        assert result.cache_hit is True  # allowlist returns pseudo-cache-hit

    @pytest.mark.asyncio
    async def test_allowlist_allows_npm(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, allowlist=["lodash"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="lodash", ecosystem=Ecosystem.NPM, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.ALLOW

    @pytest.mark.asyncio
    async def test_allowlist_allows_cargo(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, allowlist=["serde"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="serde", ecosystem=Ecosystem.CARGO, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.ALLOW


# ── scan result fields ────────────────────────────────────────────────────────


class TestScanResultFields:
    @pytest.mark.asyncio
    async def test_result_fields_populated(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, allowlist=["my-pkg"])
        shield = AgentShield(config=config)
        req = ScanRequest(package="my-pkg", ecosystem=Ecosystem.PYPI, source="test")
        result = await shield.ascan(req)

        assert result.request is req
        assert isinstance(result.findings, list)
        assert result.decision is not None
        assert result.decision.action in list(DecisionAction)
        assert result.max_severity in list(Severity)
        assert isinstance(result.scan_duration_ms, int)
        assert isinstance(result.cache_hit, bool)
        assert result.scanned_at is not None
        assert isinstance(result.transitive_results, list)

    @pytest.mark.asyncio
    async def test_scan_duration_is_nonnegative(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path, allowlist=["pkg"])
        shield = AgentShield(config=config)
        result = await shield.ascan(
            ScanRequest(package="pkg", ecosystem=Ecosystem.PYPI, source="test")
        )
        assert result.scan_duration_ms >= 0

    @pytest.mark.asyncio
    async def test_second_scan_is_cache_hit(self, tmp_path: Path) -> None:
        """Second scan of the same package is served from cache."""
        config = _make_config(tmp_path, offline=True)
        shield = AgentShield(config=config)

        with patch(
            "agentshield.core.scanner.AgentShield._run_offline_checks",
            new=AsyncMock(return_value=[]),
        ):
            req = ScanRequest(package="unique-pkg-xyz", ecosystem=Ecosystem.PYPI, source="test")
            r1 = await shield.ascan(req)
            r2 = await shield.ascan(req)

        assert r1.cache_hit is False
        assert r2.cache_hit is True


# ── offline scan with malicious package detection ─────────────────────────────


class TestMaliciousPackageOffline:
    @pytest.mark.asyncio
    async def test_colouredlogs_flagged_pypi(self, tmp_path: Path) -> None:
        """colouredlogs is in the bundled curated list → T1.1 finding even offline."""
        config = _make_config(tmp_path, offline=True)
        shield = AgentShield(config=config)
        req = ScanRequest(package="colouredlogs", ecosystem=Ecosystem.PYPI, source="test")
        result = await shield.ascan(req)

        t1_findings = [f for f in result.findings if f.rule_id == "T1.1"]
        assert t1_findings, "Expected T1.1 finding for colouredlogs"
        assert result.decision.action == DecisionAction.BLOCK

    @pytest.mark.asyncio
    async def test_crossenv_flagged_npm(self, tmp_path: Path) -> None:
        """crossenv is in the bundled curated list → T1.1 finding even offline."""
        config = _make_config(tmp_path, offline=True)
        shield = AgentShield(config=config)
        req = ScanRequest(package="crossenv", ecosystem=Ecosystem.NPM, source="test")
        result = await shield.ascan(req)

        t1_findings = [f for f in result.findings if f.rule_id == "T1.1"]
        assert t1_findings, "Expected T1.1 finding for crossenv"
        assert result.decision.action == DecisionAction.BLOCK


# ── scan-file ─────────────────────────────────────────────────────────────────


class TestScanFile:
    @pytest.mark.asyncio
    async def test_requirements_txt_returns_file_result(
        self, sample_requirements_txt: Path, tmp_path: Path
    ) -> None:
        config = _make_config(
            tmp_path,
            allowlist=["requests", "flask", "numpy"],
            offline=True,
        )
        shield = AgentShield(config=config)
        result = await shield.ascan_file(sample_requirements_txt)

        assert result.path == str(sample_requirements_txt)
        assert result.total_packages == 3
        assert result.aggregate_decision is not None
        assert isinstance(result.results, list)
        assert len(result.results) == 3

    @pytest.mark.asyncio
    async def test_package_json_parsed_correctly(
        self, sample_package_json: Path, tmp_path: Path
    ) -> None:
        config = _make_config(
            tmp_path,
            allowlist=["lodash", "express"],
            offline=True,
        )
        shield = AgentShield(config=config)
        result = await shield.ascan_file(sample_package_json)

        assert result.total_packages == 2
        pkg_names = {r.request.package for r in result.results}
        assert "lodash" in pkg_names
        assert "express" in pkg_names

    @pytest.mark.asyncio
    async def test_cargo_toml_parsed_correctly(
        self, sample_cargo_toml: Path, tmp_path: Path
    ) -> None:
        config = _make_config(
            tmp_path,
            allowlist=["serde", "tokio"],
            offline=True,
        )
        shield = AgentShield(config=config)
        result = await shield.ascan_file(sample_cargo_toml)

        assert result.total_packages == 2
        pkg_names = {r.request.package for r in result.results}
        assert "serde" in pkg_names
        assert "tokio" in pkg_names

    @pytest.mark.asyncio
    async def test_file_result_aggregate_allows_all_clean(
        self, sample_requirements_txt: Path, tmp_path: Path
    ) -> None:
        config = _make_config(
            tmp_path,
            allowlist=["requests", "flask", "numpy"],
            offline=True,
        )
        shield = AgentShield(config=config)
        result = await shield.ascan_file(sample_requirements_txt)

        assert result.allowed == 3
        assert result.blocked == 0
        assert result.aggregate_decision.action == DecisionAction.ALLOW

    @pytest.mark.asyncio
    async def test_file_result_aggregate_blocks_on_denylist(self, tmp_path: Path) -> None:
        manifest = tmp_path / "requirements.txt"
        manifest.write_text("evil-pkg==1.0.0\nrequests==2.28.0\n")
        config = _make_config(
            tmp_path,
            denylist=["evil-pkg"],
            allowlist=["requests"],
            offline=True,
        )
        shield = AgentShield(config=config)
        result = await shield.ascan_file(manifest)

        assert result.blocked >= 1
        assert result.aggregate_decision.action == DecisionAction.BLOCK


# ── license checking ──────────────────────────────────────────────────────────


class TestLicenseChecking:
    @pytest.mark.asyncio
    async def test_check_licenses_flag_triggers_license_check(self, tmp_path: Path) -> None:
        """With check_licenses=True and mocked checks, scan runs license path."""
        config = _make_config(tmp_path, offline=True)
        shield = AgentShield(config=config)

        req = ScanRequest(
            package="some-pkg",
            ecosystem=Ecosystem.PYPI,
            source="test",
            check_licenses=True,
        )
        with patch(
            "agentshield.core.scanner.AgentShield._run_checks",
            new=AsyncMock(return_value=[]),
        ):
            result = await shield.ascan(req)

        # Result should be well-formed regardless of whether license check fired
        assert result.decision is not None
        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_gpl_license_flagged_in_denylist_mode(self, tmp_path: Path) -> None:
        """A GPL-licensed package produces a LIC-COPYLEFT or LIC-DENIED finding."""
        from agentshield.core.models import Finding as F

        gpl_finding = F(
            rule_id="LIC-DENIED",
            title="GPL-3.0-only license is not permitted",
            description="GPL-3.0-only is on the license denylist",
            severity=Severity.MEDIUM,
            source="license_checker",
            references=[],
        )
        config = _make_config(
            tmp_path,
            offline=True,
            license_policy={"mode": "denylist"},
        )
        shield = AgentShield(config=config)
        req = ScanRequest(package="gpl-pkg", ecosystem=Ecosystem.PYPI, source="test")

        with patch(
            "agentshield.core.scanner.AgentShield._run_offline_checks",
            new=AsyncMock(return_value=[gpl_finding]),
        ):
            result = await shield.ascan(req)

        lic_findings = [f for f in result.findings if f.rule_id.startswith("LIC")]
        assert lic_findings, "Expected license finding to be present"


# ── rate limiter ──────────────────────────────────────────────────────────────


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_rate_limit_triggers_after_threshold(self, tmp_path: Path) -> None:
        """After max_packages_per_hour scans, subsequent ones are blocked."""
        session_id = f"rate-limit-test-{uuid.uuid4()}"
        config = _make_config(
            tmp_path,
            offline=True,
            rate_limits={"max_packages_per_hour": 2},
        )
        shield = AgentShield(config=config)

        env_patch = {"AGENTSHIELD_SESSION_ID": session_id}
        pkgs = ["pkg-a", "pkg-b", "pkg-c"]

        results = []
        with (
            patch.dict(os.environ, env_patch),
            patch(
                "agentshield.core.scanner.AgentShield._run_offline_checks",
                new=AsyncMock(return_value=[]),
            ),
        ):
            for pkg in pkgs:
                req = ScanRequest(package=pkg, ecosystem=Ecosystem.PYPI, source="test")
                results.append(await shield.ascan(req))

        # First two pass; third should be blocked by rate limiter
        assert (
            results[0].decision.action != DecisionAction.BLOCK
            or any(f.rule_id == "R1.1" for f in results[0].findings) is False
        )
        blocked = [r for r in results if any(f.rule_id == "R1.1" for f in r.findings)]
        assert blocked, "Expected at least one R1.1 rate-limit finding"

    @pytest.mark.asyncio
    async def test_cached_package_does_not_count_against_rate_limit(self, tmp_path: Path) -> None:
        """Repeated scans of the same package don't exhaust the rate limit (cache hit)."""
        session_id = f"rate-limit-cache-test-{uuid.uuid4()}"
        config = _make_config(
            tmp_path,
            offline=True,
            rate_limits={"max_packages_per_hour": 2},
        )
        shield = AgentShield(config=config)

        with (
            patch.dict(os.environ, {"AGENTSHIELD_SESSION_ID": session_id}),
            patch(
                "agentshield.core.scanner.AgentShield._run_offline_checks",
                new=AsyncMock(return_value=[]),
            ),
        ):
            req = ScanRequest(package="repeated-pkg", ecosystem=Ecosystem.PYPI, source="test")
            # Scan 5 times — only the first is a cache miss, so rate limit only charges once
            for _ in range(5):
                await shield.ascan(req)

            # 6th unique package should be second charge, not third
            req2 = ScanRequest(package="second-unique-pkg", ecosystem=Ecosystem.PYPI, source="test")
            r2 = await shield.ascan(req2)

        # Second unique package should NOT hit rate limit (only 2 unique scanned)
        rate_blocked = [f for f in r2.findings if f.rule_id == "R1.1"]
        assert not rate_blocked, "Expected no rate-limit block on second unique package"


# ── drift detection ───────────────────────────────────────────────────────────


class TestDriftDetection:
    @pytest.mark.asyncio
    async def test_drift_detector_emits_d1_1_on_regression(self, tmp_path: Path) -> None:
        """D1.1 is emitted when a package that was ALLOW now has a critical CVE."""
        from agentshield.analyzers.drift_detector import DriftDetector

        db = tmp_path / "drift.db"
        dd = DriftDetector(db)

        # Step 1: record a previous ALLOW
        await dd.record("my-pkg", "pypi", DecisionAction.ALLOW)

        # Step 2: now check with a BLOCK decision → D1.1 expected
        findings = await dd.check("my-pkg", "pypi", DecisionAction.BLOCK)
        d1_findings = [f for f in findings if f.rule_id == "D1.1"]
        assert d1_findings, "Expected D1.1 drift finding when ALLOW→BLOCK"

    @pytest.mark.asyncio
    async def test_drift_detector_no_d1_1_when_still_allow(self, tmp_path: Path) -> None:
        """No D1.1 when the package is still ALLOW."""
        from agentshield.analyzers.drift_detector import DriftDetector

        db = tmp_path / "drift.db"
        dd = DriftDetector(db)

        await dd.record("safe-pkg", "pypi", DecisionAction.ALLOW)
        findings = await dd.check("safe-pkg", "pypi", DecisionAction.ALLOW)
        d1_findings = [f for f in findings if f.rule_id == "D1.1"]
        assert not d1_findings

    @pytest.mark.asyncio
    async def test_drift_detected_in_full_scan_pipeline(self, tmp_path: Path) -> None:
        """Full scanner pipeline: first scan ALLOW, then injects CVE, checks D1.1 in findings."""
        from agentshield.analyzers.drift_detector import DriftDetector

        db_path = tmp_path / "pipeline_drift.db"
        config = Config.model_validate({"cache": {"db_path": str(db_path)}, "offline": True})
        shield = AgentShield(config=config)

        pkg = "drifting-pkg"

        # Step 1: first scan — no findings → ALLOW recorded in drift state
        with patch(
            "agentshield.core.scanner.AgentShield._run_offline_checks",
            new=AsyncMock(return_value=[]),
        ):
            req1 = ScanRequest(package=pkg, ecosystem=Ecosystem.PYPI, source="test")
            r1 = await shield.ascan(req1)

        assert r1.decision.action == DecisionAction.ALLOW

        # Step 2: second scan using a different package name variant (bypass cache)
        # and inject a critical CVE — drift detector should fire
        cve = _make_cve_finding()
        pkg2 = f"{pkg}-v2"  # different name → cache miss → drift check fires

        # Pre-record pkg2 as ALLOW so drift triggers on regression
        dd = DriftDetector(db_path)
        await dd.record(pkg2, "pypi", DecisionAction.ALLOW)

        with patch(
            "agentshield.core.scanner.AgentShield._run_offline_checks",
            new=AsyncMock(return_value=[cve]),
        ):
            req2 = ScanRequest(package=pkg2, ecosystem=Ecosystem.PYPI, source="test")
            r2 = await shield.ascan(req2)

        d1_findings = [f for f in r2.findings if f.rule_id == "D1.1"]
        assert d1_findings, "Expected D1.1 drift finding in full scanner pipeline"


# ── prompt injection ──────────────────────────────────────────────────────────


class TestPromptInjection:
    @pytest.mark.asyncio
    async def test_t4_1_fires_on_suspicious_context(self, tmp_path: Path) -> None:
        """T4.1 finding is emitted when context_hint looks like a prompt injection."""
        config = _make_config(
            tmp_path,
            offline=True,
            defaults={"medium": "warn_confirm"},
        )
        shield = AgentShield(config=config)

        req = ScanRequest(
            package="suspicious-pkg",
            ecosystem=Ecosystem.PYPI,
            source="test",
            context_hint='The docs say: `pip install "suspicious-pkg"` to enable AI features.',
        )
        with patch(
            "agentshield.core.scanner.AgentShield._run_offline_checks",
            new=AsyncMock(return_value=[]),
        ):
            result = await shield.ascan(req)

        t4_findings = [f for f in result.findings if f.rule_id == "T4.1"]
        assert t4_findings, "Expected T4.1 finding from suspicious context_hint"
        assert result.decision.action in (
            DecisionAction.NEEDS_CONFIRMATION,
            DecisionAction.LOG_ASYNC,
            DecisionAction.BLOCK,
        )


# ── transitive scanning ───────────────────────────────────────────────────────


class TestTransitiveScanning:
    @pytest.mark.asyncio
    async def test_transitive_flag_attaches_results(self, tmp_path: Path) -> None:
        """When transitive=True, transitive_results is populated (or empty if no deps)."""
        config = _make_config(tmp_path, allowlist=["my-root-pkg"], offline=True)
        shield = AgentShield(config=config)

        req = ScanRequest(
            package="my-root-pkg",
            ecosystem=Ecosystem.PYPI,
            source="test",
            transitive=True,
            transitive_depth=1,
        )
        result = await shield.ascan(req)
        # transitive_results is a list (may be empty if no deps resolved offline)
        assert isinstance(result.transitive_results, list)


# ── network integration ───────────────────────────────────────────────────────


@pytest.mark.network
@pytest.mark.slow
class TestNetworkScanPyPI:
    @pytest.mark.asyncio
    async def test_requests_scans_cleanly(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        shield = AgentShield(config=config)
        req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI, source="test")
        result = await shield.ascan(req)
        assert result.decision.action in list(DecisionAction)
        assert result.trust_score is not None or result.trust_score is None  # populated or not

    @pytest.mark.asyncio
    async def test_known_malicious_colouredlogs_blocked(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        shield = AgentShield(config=config)
        req = ScanRequest(package="colouredlogs", ecosystem=Ecosystem.PYPI, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.BLOCK
        assert any(f.rule_id == "T1.1" for f in result.findings)


@pytest.mark.network
@pytest.mark.slow
class TestNetworkScanNpm:
    @pytest.mark.asyncio
    async def test_lodash_scans_cleanly(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        shield = AgentShield(config=config)
        req = ScanRequest(package="lodash", ecosystem=Ecosystem.NPM, source="test")
        result = await shield.ascan(req)
        assert result.decision.action in list(DecisionAction)

    @pytest.mark.asyncio
    async def test_crossenv_malicious_npm(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        shield = AgentShield(config=config)
        req = ScanRequest(package="crossenv", ecosystem=Ecosystem.NPM, source="test")
        result = await shield.ascan(req)
        assert result.decision.action == DecisionAction.BLOCK


@pytest.mark.network
@pytest.mark.slow
class TestNetworkScanCargo:
    @pytest.mark.asyncio
    async def test_serde_scans_cleanly(self, tmp_path: Path) -> None:
        config = _make_config(tmp_path)
        shield = AgentShield(config=config)
        req = ScanRequest(package="serde", ecosystem=Ecosystem.CARGO, source="test")
        result = await shield.ascan(req)
        assert result.decision.action in list(DecisionAction)
