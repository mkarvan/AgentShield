import pytest

from agentshield.analyzers.typosquatting import TyposquattingChecker
from agentshield.core.models import Ecosystem, ScanRequest


def _req(name: str) -> ScanRequest:
    return ScanRequest(package=name, ecosystem=Ecosystem.PYPI)


@pytest.mark.asyncio
async def test_exact_match_not_flagged(monkeypatch):
    checker = TyposquattingChecker()
    checker._known = {"pypi": ["requests"]}
    findings = await checker.scan(_req("requests"))
    assert findings == []


@pytest.mark.asyncio
async def test_close_name_flagged(monkeypatch):
    checker = TyposquattingChecker()
    checker._known = {"pypi": ["requests"]}
    findings = await checker.scan(_req("reqests"))  # 1 edit away
    assert len(findings) == 1
    assert findings[0].rule_id == "T1.2"
    assert "requests" in findings[0].title


@pytest.mark.asyncio
async def test_distant_name_not_flagged(monkeypatch):
    checker = TyposquattingChecker()
    checker._known = {"pypi": ["requests"]}
    findings = await checker.scan(_req("completely_different_package"))
    assert findings == []


@pytest.mark.asyncio
async def test_hyphen_underscore_normalized(monkeypatch):
    checker = TyposquattingChecker()
    checker._known = {"pypi": ["my-package"]}
    # "my_package" should match "my-package" exactly after normalization
    findings = await checker.scan(_req("my_package"))
    assert findings == []
