"""Integration tests for the GitHub Advisory Database GraphQL client.

These tests make real HTTP requests to the GitHub API. They require a
GitHub token (any personal access token with no special scopes works).

  GITHUB_TOKEN=ghp_... pytest tests/integration/test_github_advisory.py -m integration

Without a token, the client returns [] gracefully — that behaviour is also
tested here to verify the no-token path doesn't crash.
"""

from __future__ import annotations

import os

import pytest

from agentshield.core.models import Ecosystem, ScanRequest, Severity
from agentshield.databases.github_advisory import GitHubAdvisoryClient

pytestmark = pytest.mark.integration

_VALID_SEVERITIES = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW}


@pytest.fixture
def gh_client() -> GitHubAdvisoryClient:
    token = os.environ.get("GITHUB_TOKEN")
    return GitHubAdvisoryClient(token=token)


@pytest.mark.asyncio
async def test_scan_without_token_returns_empty():
    """Without a token the client should return [] (graceful degradation)."""
    client = GitHubAdvisoryClient(token=None)
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)
    findings = await client.scan(req)
    assert findings == []


@pytest.mark.asyncio
async def test_scan_returns_list(gh_client: GitHubAdvisoryClient):
    """Smoke test: scan returns a list without raising."""
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)
    findings = await gh_client.scan(req)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_scan_pillow_has_advisories(gh_client: GitHubAdvisoryClient):
    """Pillow has many historical advisories — expect at least one."""
    if not os.environ.get("GITHUB_TOKEN"):
        pytest.skip("GITHUB_TOKEN not set")
    req = ScanRequest(package="Pillow", ecosystem=Ecosystem.PYPI)
    findings = await gh_client.scan(req)
    assert len(findings) > 0


@pytest.mark.asyncio
async def test_findings_have_expected_fields(gh_client: GitHubAdvisoryClient):
    """All findings should have required fields and correct source."""
    if not os.environ.get("GITHUB_TOKEN"):
        pytest.skip("GITHUB_TOKEN not set")
    req = ScanRequest(package="django", ecosystem=Ecosystem.PYPI)
    findings = await gh_client.scan(req)
    for f in findings:
        assert f.rule_id  # CVE-YYYY-NNNNN or GHSA-...
        assert f.severity in _VALID_SEVERITIES
        assert f.source == "github_advisory"


@pytest.mark.asyncio
async def test_scan_npm_lodash(gh_client: GitHubAdvisoryClient):
    """lodash (npm) has known prototype pollution advisories."""
    if not os.environ.get("GITHUB_TOKEN"):
        pytest.skip("GITHUB_TOKEN not set")
    req = ScanRequest(package="lodash", ecosystem=Ecosystem.NPM)
    findings = await gh_client.scan(req)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_scan_nonexistent_package(gh_client: GitHubAdvisoryClient):
    """An unknown package should return an empty list, not raise."""
    if not os.environ.get("GITHUB_TOKEN"):
        pytest.skip("GITHUB_TOKEN not set")
    req = ScanRequest(package="agentshield-xyzzy-nonexistent-pkg", ecosystem=Ecosystem.PYPI)
    findings = await gh_client.scan(req)
    assert findings == []
