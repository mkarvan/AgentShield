"""Integration tests for the NVD API v2 client.

These tests make real HTTP requests to the NVD API. They are skipped by
default and only run when marked explicitly:

  pytest tests/integration/test_nvd.py -m integration

Tip: set NVD_API_KEY to avoid rate-limiting during repeated test runs.
"""

from __future__ import annotations

import os

import pytest

from agentshield.core.models import Ecosystem, ScanRequest, Severity
from agentshield.databases.nvd import NVD429Error, NVDClient

pytestmark = pytest.mark.integration

_VALID_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}


@pytest.fixture
def nvd_client() -> NVDClient:
    api_key = os.environ.get("NVD_API_KEY")
    return NVDClient(api_key=api_key)


@pytest.mark.asyncio
async def test_nvd_scan_returns_list(nvd_client: NVDClient):
    """Smoke test: scan returns a list without raising."""
    req = ScanRequest(package="requests", version="2.6.0", ecosystem=Ecosystem.PYPI)
    try:
        findings = await nvd_client.scan(req)
    except NVD429Error:
        pytest.skip("NVD rate-limiting")
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_nvd_scan_clean_package(nvd_client: NVDClient):
    """A package name unlikely to appear in any CVE descriptions."""
    req = ScanRequest(package="agentshield-test-pkg-xyzzy", ecosystem=Ecosystem.PYPI)
    findings = await nvd_client.scan(req)
    assert findings == []


@pytest.mark.asyncio
async def test_nvd_scan_with_api_key():
    """Verify the API key path doesn't crash."""
    api_key = os.environ.get("NVD_API_KEY", "test-key-value")
    client = NVDClient(api_key=api_key)
    req = ScanRequest(package="flask", ecosystem=Ecosystem.PYPI)
    findings = await client.scan(req)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_nvd_findings_have_expected_fields(nvd_client: NVDClient):
    """Any returned findings should have the required Finding fields populated."""
    req = ScanRequest(package="pillow", ecosystem=Ecosystem.PYPI)
    findings = await nvd_client.scan(req)
    for f in findings:
        assert f.rule_id.startswith("CVE-")
        assert f.severity in _VALID_SEVERITIES
        assert f.source == "nvd"
