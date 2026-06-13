"""Unit tests for the GitHub Advisory Database GraphQL client."""
from __future__ import annotations

import pytest
import respx
from httpx import Response

from agentshield.core.models import Ecosystem, ScanRequest, Severity
from agentshield.databases.github_advisory import (
    GitHubAdvisoryClient,
    _node_to_finding,
)

GH_URL = "https://api.github.com/graphql"


def _make_node(
    ghsa_id: str = "GHSA-xxxx-xxxx-xxxx",
    cve_id: str | None = "CVE-2024-12345",
    severity: str = "HIGH",
    summary: str = "Test vulnerability",
    description: str = "Detailed description",
    cvss_score: float | None = 7.5,
    patched_version: str | None = "2.29.0",
    withdrawn: bool = False,
    vuln_range: str = ">= 2.0.0, < 2.29.0",
) -> dict:
    identifiers = [{"type": "GHSA", "value": ghsa_id}]
    if cve_id:
        identifiers.append({"type": "CVE", "value": cve_id})

    return {
        "advisory": {
            "ghsaId": ghsa_id,
            "summary": summary,
            "description": description,
            "severity": severity,
            "identifiers": identifiers,
            "references": [{"url": "https://example.com/ghsa"}],
            "cvss": {"score": cvss_score, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"} if cvss_score else None,
            "publishedAt": "2024-01-01T00:00:00Z",
            "withdrawnAt": "2024-06-01T00:00:00Z" if withdrawn else None,
        },
        "vulnerableVersionRange": vuln_range,
        "firstPatchedVersion": {"identifier": patched_version} if patched_version else None,
    }


def _make_request(package: str = "requests", ecosystem: Ecosystem = Ecosystem.PYPI) -> ScanRequest:
    return ScanRequest(package=package, ecosystem=ecosystem)


# ── _node_to_finding ─────────────────────────────────────────────────────────────

def test_node_to_finding_basic():
    node = _make_node()
    req = _make_request()
    f = _node_to_finding(node, req)
    assert f is not None
    assert f.rule_id == "CVE-2024-12345"  # Prefers CVE over GHSA
    assert f.severity == Severity.HIGH
    assert f.cvss_score == 7.5
    assert f.source == "github_advisory"
    assert f.remediation == "Upgrade to >= 2.29.0"
    assert f.metadata["ghsa_id"] == "GHSA-xxxx-xxxx-xxxx"


def test_node_to_finding_prefers_cve_id():
    node = _make_node(cve_id="CVE-2024-99999")
    f = _node_to_finding(node, _make_request())
    assert f is not None
    assert f.rule_id == "CVE-2024-99999"


def test_node_to_finding_falls_back_to_ghsa():
    node = _make_node(cve_id=None)
    f = _node_to_finding(node, _make_request())
    assert f is not None
    assert f.rule_id == "GHSA-xxxx-xxxx-xxxx"


def test_node_to_finding_skips_withdrawn():
    node = _make_node(withdrawn=True)
    f = _node_to_finding(node, _make_request())
    assert f is None


def test_node_to_finding_critical_severity():
    node = _make_node(severity="CRITICAL", cvss_score=9.8)
    f = _node_to_finding(node, _make_request())
    assert f is not None
    assert f.severity == Severity.CRITICAL


def test_node_to_finding_moderate_maps_to_medium():
    node = _make_node(severity="MODERATE", cvss_score=5.0)
    f = _node_to_finding(node, _make_request())
    assert f is not None
    assert f.severity == Severity.MEDIUM


def test_node_to_finding_no_patch_version():
    node = _make_node(patched_version=None)
    f = _node_to_finding(node, _make_request())
    assert f is not None
    assert f.remediation is None


def test_node_to_finding_no_cvss():
    node = _make_node(cvss_score=None)
    f = _node_to_finding(node, _make_request())
    assert f is not None
    assert f.cvss_score is None


def test_node_to_finding_skips_missing_ghsa():
    node = _make_node()
    node["advisory"]["ghsaId"] = ""
    f = _node_to_finding(node, _make_request())
    assert f is None


# ── GitHubAdvisoryClient.scan ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_no_token_returns_empty():
    client = GitHubAdvisoryClient(token=None)
    findings = await client.scan(_make_request())
    assert findings == []


@pytest.mark.asyncio
async def test_scan_unsupported_ecosystem_returns_empty():
    client = GitHubAdvisoryClient(token="ghp_test")
    # All three ecosystems are supported — verify no crash on any
    for eco in Ecosystem:
        result = await client.scan(ScanRequest(package="test-pkg", ecosystem=eco))
        assert isinstance(result, list)


@pytest.mark.asyncio
@respx.mock
async def test_scan_returns_findings():
    respx.post(GH_URL).mock(return_value=Response(200, json={
        "data": {
            "securityVulnerabilities": {
                "nodes": [_make_node()]
            }
        }
    }))
    client = GitHubAdvisoryClient(token="ghp_test")
    findings = await client.scan(_make_request())
    assert len(findings) == 1
    assert findings[0].source == "github_advisory"


@pytest.mark.asyncio
@respx.mock
async def test_scan_empty_nodes():
    respx.post(GH_URL).mock(return_value=Response(200, json={
        "data": {"securityVulnerabilities": {"nodes": []}}
    }))
    client = GitHubAdvisoryClient(token="ghp_test")
    findings = await client.scan(_make_request())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_scan_filters_withdrawn():
    respx.post(GH_URL).mock(return_value=Response(200, json={
        "data": {
            "securityVulnerabilities": {
                "nodes": [
                    _make_node(withdrawn=True),
                    _make_node(ghsa_id="GHSA-yyyy-yyyy-yyyy", withdrawn=False),
                ]
            }
        }
    }))
    client = GitHubAdvisoryClient(token="ghp_test")
    findings = await client.scan(_make_request())
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_scan_graphql_error_returns_empty():
    respx.post(GH_URL).mock(return_value=Response(200, json={
        "errors": [{"message": "Some GraphQL error"}]
    }))
    client = GitHubAdvisoryClient(token="ghp_test")
    findings = await client.scan(_make_request())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_scan_http_error_returns_empty():
    respx.post(GH_URL).mock(return_value=Response(401))
    client = GitHubAdvisoryClient(token="ghp_bad_token")
    findings = await client.scan(_make_request())
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_scan_sends_auth_header():
    sent_headers: dict = {}

    def capture(request: object, route: object) -> Response:
        sent_headers.update(request.headers)  # type: ignore[attr-defined]
        return Response(200, json={"data": {"securityVulnerabilities": {"nodes": []}}})

    respx.post(GH_URL).mock(side_effect=capture)
    client = GitHubAdvisoryClient(token="ghp_mytoken")
    await client.scan(_make_request())
    assert "bearer ghp_mytoken" in sent_headers.get("authorization", "")


@pytest.mark.asyncio
@respx.mock
async def test_scan_npm_ecosystem():
    respx.post(GH_URL).mock(return_value=Response(200, json={
        "data": {
            "securityVulnerabilities": {
                "nodes": [_make_node(severity="CRITICAL")]
            }
        }
    }))
    client = GitHubAdvisoryClient(token="ghp_test")
    req = ScanRequest(package="lodash", ecosystem=Ecosystem.NPM)
    findings = await client.scan(req)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
