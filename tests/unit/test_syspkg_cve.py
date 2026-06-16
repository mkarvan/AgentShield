"""Unit tests for analyzers/syspkg_cve.py."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agentshield.analyzers.syspkg_cve import (
    SysPkgCVEScanner,
    _cache_key,
    _dedupe_findings,
    _extract_osv_severity,
    _osv_vuln_to_finding,
    _parse_cvss3_score,
    _safe_float,
    _severity_from_cvss,
)
from agentshield.analyzers.syspkg_detector import SysPkgWarning
from agentshield.core.models import Finding, Severity

# ── helper factories ─────────────────────────────────────────────────────────


def _make_warning(manager: str = "apt-get", packages: list[str] | None = None) -> SysPkgWarning:
    return SysPkgWarning(
        manager=manager,
        packages=packages or ["curl"],
        raw_fragment=f"{manager} install curl",
    )


def _make_osv_vuln(
    vuln_id: str = "DSA-5000-1",
    summary: str = "Test vulnerability",
    severity: str = "HIGH",
    cvss_vector: str | None = None,
    vuln_type: str = "",
) -> dict[str, Any]:
    vuln: dict[str, Any] = {
        "id": vuln_id,
        "summary": summary,
        "details": "Detailed description of the vulnerability.",
        "database_specific": {"severity": severity},
        "references": [{"url": f"https://example.com/{vuln_id}"}],
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "1.2.3"},
                        ]
                    }
                ]
            }
        ],
    }
    if vuln_type:
        vuln["database_specific"]["type"] = vuln_type
    if cvss_vector:
        vuln["severity"] = [{"type": "CVSS_V3", "score": cvss_vector}]
    return vuln


# ── _osv_vuln_to_finding ────────────────────────────────────────────────────


class TestOsvVulnToFinding:
    def test_basic_conversion(self) -> None:
        vuln = _make_osv_vuln()
        finding = _osv_vuln_to_finding(vuln, "Debian")
        assert finding.rule_id == "DSA-5000-1"
        assert finding.severity == Severity.HIGH
        assert finding.source == "osv/debian"
        assert "1.2.3" in (finding.remediation or "")
        assert finding.metadata["ecosystem"] == "Debian"

    def test_malicious_type(self) -> None:
        vuln = _make_osv_vuln(vuln_type="MALICIOUS")
        finding = _osv_vuln_to_finding(vuln, "Ubuntu")
        assert finding.severity == Severity.CRITICAL
        assert finding.rule_id.startswith("SP-MAL-")

    def test_references_extracted(self) -> None:
        vuln = _make_osv_vuln()
        finding = _osv_vuln_to_finding(vuln, "Debian")
        assert len(finding.references) == 1
        assert "example.com" in finding.references[0]


# ── _extract_osv_severity ───────────────────────────────────────────────────


class TestExtractOsvSeverity:
    def test_from_database_specific(self) -> None:
        vuln = _make_osv_vuln(severity="CRITICAL")
        sev, score = _extract_osv_severity(vuln)
        assert sev == Severity.CRITICAL
        assert score is None

    def test_moderate_maps_to_medium(self) -> None:
        vuln = _make_osv_vuln(severity="MODERATE")
        sev, _ = _extract_osv_severity(vuln)
        assert sev == Severity.MEDIUM

    def test_cvss_vector_extracts_score(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        vuln = _make_osv_vuln(severity="", cvss_vector=vector)
        sev, score = _extract_osv_severity(vuln)
        assert score is not None
        assert score >= 9.0
        assert sev == Severity.CRITICAL

    def test_default_medium_when_no_severity(self) -> None:
        vuln: dict[str, Any] = {"id": "TEST-1", "database_specific": {}}
        sev, _ = _extract_osv_severity(vuln)
        assert sev == Severity.MEDIUM


# ── _severity_from_cvss ─────────────────────────────────────────────────────


class TestSeverityFromCvss:
    def test_critical(self) -> None:
        assert _severity_from_cvss(9.5) == Severity.CRITICAL

    def test_high(self) -> None:
        assert _severity_from_cvss(7.5) == Severity.HIGH

    def test_medium(self) -> None:
        assert _severity_from_cvss(5.0) == Severity.MEDIUM

    def test_low(self) -> None:
        assert _severity_from_cvss(2.0) == Severity.LOW

    def test_info(self) -> None:
        assert _severity_from_cvss(0.0) == Severity.INFO


# ── _parse_cvss3_score ──────────────────────────────────────────────────────


class TestParseCvss3Score:
    def test_valid_vector(self) -> None:
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = _parse_cvss3_score(vector)
        assert score is not None
        assert 9.0 <= score <= 10.0

    def test_invalid_prefix(self) -> None:
        assert _parse_cvss3_score("CVSS:2.0/something") is None

    def test_garbage(self) -> None:
        assert _parse_cvss3_score("not-a-vector") is None

    def test_empty(self) -> None:
        assert _parse_cvss3_score("") is None


# ── _safe_float ─────────────────────────────────────────────────────────────


class TestSafeFloat:
    def test_valid(self) -> None:
        assert _safe_float("7.5") == 7.5

    def test_none(self) -> None:
        assert _safe_float(None) is None

    def test_out_of_range(self) -> None:
        assert _safe_float("15.0") is None

    def test_garbage(self) -> None:
        assert _safe_float("abc") is None


# ── _dedupe_findings ─────────────────────────────────────────────────────────


class TestDedupeFindings:
    def test_deduplicates_by_rule_id(self) -> None:
        f1 = Finding(
            rule_id="CVE-1",
            title="t1",
            severity=Severity.LOW,
            source="a",
        )
        f2 = Finding(
            rule_id="CVE-1",
            title="t2",
            severity=Severity.HIGH,
            source="b",
        )
        result = _dedupe_findings([f1, f2])
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH

    def test_keeps_distinct(self) -> None:
        f1 = Finding(rule_id="CVE-1", title="t1", severity=Severity.LOW, source="a")
        f2 = Finding(rule_id="CVE-2", title="t2", severity=Severity.HIGH, source="b")
        result = _dedupe_findings([f1, f2])
        assert len(result) == 2


# ── _cache_key ───────────────────────────────────────────────────────────────


class TestCacheKey:
    def test_deterministic(self) -> None:
        k1 = _cache_key("curl", "apt-get")
        k2 = _cache_key("curl", "apt-get")
        assert k1 == k2

    def test_different_for_different_inputs(self) -> None:
        k1 = _cache_key("curl", "apt-get")
        k2 = _cache_key("wget", "apt-get")
        assert k1 != k2

    def test_different_for_different_managers(self) -> None:
        k1 = _cache_key("curl", "apt-get")
        k2 = _cache_key("curl", "brew")
        assert k1 != k2


# ── SysPkgCVEScanner ────────────────────────────────────────────────────────


class TestSysPkgCVEScanner:
    """Integration-style tests using mocked HTTP responses."""

    @pytest.fixture
    def db_path(self, tmp_path: Path) -> Path:
        return tmp_path / "test.db"

    @pytest.fixture
    def scanner(self, db_path: Path) -> SysPkgCVEScanner:
        return SysPkgCVEScanner(db_path=db_path, ttl=3600)

    def test_scan_warnings_empty(self, scanner: SysPkgCVEScanner) -> None:
        result = asyncio.run(scanner.scan_warnings([]))
        assert result == []

    def test_scan_warnings_no_packages(self, scanner: SysPkgCVEScanner) -> None:
        warning = SysPkgWarning(manager="apt-get", packages=[])
        result = asyncio.run(scanner.scan_warnings([warning]))
        assert result == []

    @patch("agentshield.analyzers.syspkg_cve.with_retry")
    def test_osv_findings_returned(self, mock_retry: MagicMock, scanner: SysPkgCVEScanner) -> None:
        """OSV returns vulns → scanner returns findings."""
        vuln = _make_osv_vuln(vuln_id="DSA-5000-1", severity="CRITICAL")

        async def _fake_retry(fn: Any, **kwargs: Any) -> list[Finding]:
            return [_osv_vuln_to_finding(vuln, "Debian")]

        mock_retry.side_effect = _fake_retry

        warning = _make_warning("apt-get", ["curl"])
        result = asyncio.run(scanner.scan_warnings([warning]))
        assert len(result) >= 1
        assert any(f.rule_id == "DSA-5000-1" for f in result)

    @patch("agentshield.analyzers.syspkg_cve.with_retry")
    def test_cache_hit(self, mock_retry: MagicMock, scanner: SysPkgCVEScanner) -> None:
        """Second call for same package should use cache."""
        vuln = _make_osv_vuln(vuln_id="DSA-6000-1", severity="HIGH")

        call_count = 0

        async def _fake_retry(fn: Any, **kwargs: Any) -> list[Finding]:
            nonlocal call_count
            call_count += 1
            return [_osv_vuln_to_finding(vuln, "Debian")]

        mock_retry.side_effect = _fake_retry

        warning = _make_warning("apt-get", ["wget"])
        # First call — populates cache
        asyncio.run(scanner.scan_warnings([warning]))
        first_count = call_count

        # Second call — should hit cache, no new retry calls
        asyncio.run(scanner.scan_warnings([warning]))
        assert call_count == first_count  # no additional HTTP calls

    @patch("agentshield.analyzers.syspkg_cve.with_retry")
    def test_osv_error_graceful(self, mock_retry: MagicMock, scanner: SysPkgCVEScanner) -> None:
        """OSV errors should not crash the scanner."""

        async def _fake_retry(fn: Any, **kwargs: Any) -> list[Finding]:
            raise Exception("OSV timeout")

        mock_retry.side_effect = _fake_retry

        warning = _make_warning("apt-get", ["curl"])
        result = asyncio.run(scanner.scan_warnings([warning]))
        assert result == []  # graceful degradation

    @patch("agentshield.analyzers.syspkg_cve.with_retry")
    def test_brew_no_osv_ecosystem(self, mock_retry: MagicMock, scanner: SysPkgCVEScanner) -> None:
        """Homebrew has no OSV ecosystem — should still try supplementary."""

        async def _fake_retry(fn: Any, **kwargs: Any) -> list[Finding]:
            # Homebrew formulae API returns 404 for unknown package
            return []

        mock_retry.side_effect = _fake_retry

        warning = _make_warning("brew", ["jq"])
        result = asyncio.run(scanner.scan_warnings([warning]))
        # Should complete without error even with no OSV ecosystem
        assert isinstance(result, list)

    @patch("agentshield.analyzers.syspkg_cve.with_retry")
    def test_multiple_packages_scanned(
        self, mock_retry: MagicMock, scanner: SysPkgCVEScanner
    ) -> None:
        """Multiple packages in one warning should all be scanned."""
        vuln1 = _make_osv_vuln(vuln_id="DSA-1001", severity="HIGH")
        vuln2 = _make_osv_vuln(vuln_id="DSA-1002", severity="MEDIUM")

        call_idx = 0

        async def _fake_retry(fn: Any, **kwargs: Any) -> list[Finding]:
            nonlocal call_idx
            label = kwargs.get("label", "")
            if "curl" in label:
                return [_osv_vuln_to_finding(vuln1, "Debian")]
            if "wget" in label:
                return [_osv_vuln_to_finding(vuln2, "Debian")]
            return []

        mock_retry.side_effect = _fake_retry

        warning = _make_warning("apt-get", ["curl", "wget"])
        result = asyncio.run(scanner.scan_warnings([warning]))
        rule_ids = {f.rule_id for f in result}
        assert "DSA-1001" in rule_ids
        assert "DSA-1002" in rule_ids


# ── Config integration ───────────────────────────────────────────────────────


class TestSysPkgConfig:
    def test_default_config_has_syspkg(self) -> None:
        from agentshield.core.config import Config

        cfg = Config()
        # Detection is on by default; CVE scanning is opt-in (off by default).
        assert cfg.syspkg.enabled is True
        assert cfg.syspkg.cve_scan is False
        # Severity floor + findings cap defaults keep opt-in scanning quiet.
        assert cfg.syspkg.severity_floor.value == "HIGH"
        assert cfg.syspkg.max_findings == 50
        assert cfg.syspkg.severity_policy.critical.value == "block"
        assert cfg.syspkg.severity_policy.high.value == "warn_confirm"

    def test_severity_floor_and_cap_from_toml(self, tmp_path: Path) -> None:
        from agentshield.core.config import Config

        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text(
            """\
[syspkg]
enabled = true
cve_scan = true
severity_floor = "MEDIUM"
max_findings = 10
"""
        )
        cfg = Config.load(cfg_path)
        assert cfg.syspkg.cve_scan is True
        assert cfg.syspkg.severity_floor.value == "MEDIUM"
        assert cfg.syspkg.max_findings == 10

    def test_config_from_toml(self, tmp_path: Path) -> None:
        from agentshield.core.config import Config

        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text(
            """\
[syspkg]
enabled = true
cve_scan = true

[syspkg.severity_policy]
critical = "block"
high = "block"
medium = "warn_confirm"
low = "ignore"
info = "ignore"
"""
        )
        cfg = Config.load(cfg_path)
        assert cfg.syspkg.severity_policy.high.value == "block"
        assert cfg.syspkg.severity_policy.medium.value == "warn_confirm"

    def test_config_disabled(self, tmp_path: Path) -> None:
        from agentshield.core.config import Config

        cfg_path = tmp_path / "config.toml"
        cfg_path.write_text(
            """\
[syspkg]
enabled = false
cve_scan = false
"""
        )
        cfg = Config.load(cfg_path)
        assert cfg.syspkg.enabled is False
        assert cfg.syspkg.cve_scan is False
