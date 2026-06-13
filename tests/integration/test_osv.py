"""Integration tests for the OSV client — require network access.

Run with: pytest tests/integration/ -m integration
Skip in CI without network: pytest -m "not integration"
"""
import pytest

from agentshield.core.models import Ecosystem, ScanRequest, Severity
from agentshield.databases.osv import OSVClient

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_known_vulnerable_package():
    """Pillow 9.5.0 has known CVEs — OSV should return findings."""
    client = OSVClient()
    request = ScanRequest(package="Pillow", version="9.5.0", ecosystem=Ecosystem.PYPI)
    findings = await client.scan(request)
    assert len(findings) > 0
    severities = {f.severity for f in findings}
    assert Severity.HIGH in severities or Severity.CRITICAL in severities


@pytest.mark.asyncio
async def test_clean_recent_package():
    """A clean, well-maintained package should return no malicious findings."""
    client = OSVClient()
    # httpx 0.27.0 is expected to be clean
    request = ScanRequest(package="httpx", version="0.27.0", ecosystem=Ecosystem.PYPI)
    findings = await client.scan(request)
    # Should not have T1.1 (malicious) findings
    malicious = [f for f in findings if f.rule_id == "T1.1"]
    assert malicious == []
