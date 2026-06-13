"""Unit tests for the OSV client — all HTTP calls are mocked via respx."""
from __future__ import annotations

import pytest
import respx
from httpx import HTTPStatusError, Response

from agentshield.core.models import Ecosystem, ScanRequest, Severity
from agentshield.databases.osv import OSVClient, _cvss3_base_score, _extract_severity

OSV_URL = "https://api.osv.dev/v1/query"


def _req(package: str = "requests", version: str | None = "2.28.0") -> ScanRequest:
    return ScanRequest(package=package, version=version, ecosystem=Ecosystem.PYPI)


# ── CVSS v3 base score calculator ────────────────────────────────────────────

@pytest.mark.parametrize(
    "vector,expected_min,expected_max",
    [
        # MODERATE (≈5.3) — AV:N, AC:H, PR:N, UI:R, S:U, C:H, I:N, A:N
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 4.9, 5.9),
        # CRITICAL (≈9.8) — AV:N, AC:L, PR:N, UI:N, S:U, C:H, I:H, A:H
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.5, 10.0),
        # LOW (≈3.7) — AV:N, AC:H, PR:N, UI:N, S:U, C:N, I:L, A:N
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 3.0, 4.5),
        # Zero impact score
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, 0.0),
    ],
)
def test_cvss3_base_score(vector: str, expected_min: float, expected_max: float):
    score = _cvss3_base_score(vector)
    assert score is not None
    assert expected_min <= score <= expected_max, f"Expected [{expected_min}, {expected_max}], got {score}"


def test_cvss3_invalid_vector_returns_none():
    assert _cvss3_base_score("not a cvss vector") is None
    assert _cvss3_base_score("") is None
    assert _cvss3_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C") is None


# ── _extract_severity ─────────────────────────────────────────────────────────

def test_extract_severity_from_database_specific():
    vuln = {"database_specific": {"severity": "HIGH"}, "severity": []}
    sev, _ = _extract_severity(vuln)
    assert sev == Severity.HIGH


def test_extract_severity_moderate_maps_to_medium():
    vuln = {"database_specific": {"severity": "MODERATE"}, "severity": []}
    sev, _ = _extract_severity(vuln)
    assert sev == Severity.MEDIUM


def test_extract_severity_falls_back_to_cvss_score():
    # No database_specific.severity, but has CVSS vector with high score
    vuln = {
        "database_specific": {},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    sev, score = _extract_severity(vuln)
    assert sev == Severity.CRITICAL
    assert score is not None and score >= 9.0


def test_extract_severity_default_is_medium():
    vuln = {"database_specific": {}, "severity": []}
    sev, score = _extract_severity(vuln)
    assert sev == Severity.MEDIUM
    assert score is None


# ── OSVClient (mocked HTTP) ───────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_no_vulns_returns_empty():
    respx.post(OSV_URL).mock(return_value=Response(200, json={"vulns": []}))
    client = OSVClient()
    findings = await client.scan(_req())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_single_vuln_parsed():
    respx.post(OSV_URL).mock(return_value=Response(200, json={
        "vulns": [{
            "id": "GHSA-1234-5678-9abc",
            "summary": "Test vulnerability",
            "details": "Some details",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "database_specific": {"severity": "CRITICAL"},
            "references": [{"url": "https://example.com/advisory"}],
            "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.30.0"}]}]}],
        }]
    }))
    client = OSVClient()
    findings = await client.scan(_req())
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "GHSA-1234-5678-9abc"
    assert f.severity == Severity.CRITICAL
    assert f.source == "osv"
    assert f.remediation == "Upgrade to >= 2.30.0"
    assert "https://example.com/advisory" in f.references


@pytest.mark.asyncio
@respx.mock
async def test_malicious_package_classified_as_t1_1():
    respx.post(OSV_URL).mock(return_value=Response(200, json={
        "vulns": [{
            "id": "MAL-2024-1234",
            "summary": "Malicious package",
            "details": "",
            "severity": [],
            "database_specific": {"type": "MALICIOUS", "severity": "CRITICAL"},
            "references": [],
            "affected": [],
        }]
    }))
    client = OSVClient()
    findings = await client.scan(_req(package="colouredlogs"))
    assert len(findings) == 1
    assert findings[0].rule_id == "T1.1"
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
@respx.mock
async def test_http_error_propagates():
    respx.post(OSV_URL).mock(return_value=Response(500))
    client = OSVClient()
    with pytest.raises(HTTPStatusError):
        await client.scan(_req())


@pytest.mark.asyncio
@respx.mock
async def test_multiple_vulns_all_returned():
    respx.post(OSV_URL).mock(return_value=Response(200, json={
        "vulns": [
            {"id": "CVE-A", "summary": "A", "severity": [], "database_specific": {"severity": "HIGH"}, "references": [], "affected": []},
            {"id": "CVE-B", "summary": "B", "severity": [], "database_specific": {"severity": "MEDIUM"}, "references": [], "affected": []},
        ]
    }))
    client = OSVClient()
    findings = await client.scan(_req())
    assert len(findings) == 2
    ids = {f.rule_id for f in findings}
    assert ids == {"CVE-A", "CVE-B"}
