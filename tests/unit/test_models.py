"""Unit tests for core Pydantic models."""
import pytest
from pydantic import ValidationError

from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)

# ── Severity ordering ────────────────────────────────────────────────────────

def test_severity_order():
    assert Severity.NONE < Severity.INFO < Severity.LOW
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_severity_eq():
    assert Severity.HIGH == Severity.HIGH
    assert Severity.HIGH != Severity.LOW


def test_severity_max():
    sevs = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
    assert max(sevs) == Severity.CRITICAL


def test_severity_le_ge():
    assert Severity.HIGH <= Severity.HIGH
    assert Severity.HIGH <= Severity.CRITICAL
    assert Severity.CRITICAL >= Severity.HIGH
    assert Severity.MEDIUM >= Severity.MEDIUM


def test_severity_comparison_with_non_severity_returns_not_implemented():
    result = Severity.HIGH.__lt__("not a severity")
    assert result is NotImplemented
    result = Severity.HIGH.__le__("not a severity")
    assert result is NotImplemented
    result = Severity.HIGH.__gt__("not a severity")
    assert result is NotImplemented
    result = Severity.HIGH.__ge__("not a severity")
    assert result is NotImplemented
    result = Severity.HIGH.__eq__("not a severity")
    assert result is NotImplemented


def test_severity_hashable():
    seen = {Severity.HIGH, Severity.CRITICAL, Severity.HIGH}
    assert len(seen) == 2
    mapping = {Severity.CRITICAL: "crit", Severity.HIGH: "high"}
    assert mapping[Severity.CRITICAL] == "crit"


# ── Finding validation ────────────────────────────────────────────────────────

def _finding(**overrides) -> Finding:
    defaults = dict(
        rule_id="T1.2",
        title="Test finding",
        description="desc",
        severity=Severity.MEDIUM,
        source="test",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_finding_valid():
    f = _finding()
    assert f.rule_id == "T1.2"
    assert f.cvss_score is None


def test_finding_cvss_valid():
    f = _finding(cvss_score=7.5)
    assert f.cvss_score == 7.5


def test_finding_cvss_out_of_range():
    with pytest.raises(ValidationError):
        _finding(cvss_score=10.1)

    with pytest.raises(ValidationError):
        _finding(cvss_score=-0.1)


def test_finding_empty_rule_id():
    with pytest.raises(ValidationError):
        _finding(rule_id="")


def test_finding_deduplicates_references():
    f = _finding(references=["http://example.com", "http://example.com", "http://other.com"])
    assert f.references == ["http://example.com", "http://other.com"]


def test_finding_filters_empty_references():
    f = _finding(references=["", "http://example.com", ""])
    assert f.references == ["http://example.com"]


# ── ScanRequest validation ────────────────────────────────────────────────────

def test_scan_request_basic():
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)
    assert req.package == "requests"
    assert req.version is None


def test_scan_request_with_version():
    req = ScanRequest(package="requests", version="2.28.0", ecosystem=Ecosystem.PYPI)
    assert req.version == "2.28.0"


def test_scan_request_strips_whitespace():
    req = ScanRequest(package="  requests  ", version="  2.28.0  ", ecosystem=Ecosystem.PYPI)
    assert req.package == "requests"
    assert req.version == "2.28.0"


def test_scan_request_empty_version_becomes_none():
    req = ScanRequest(package="requests", version="   ", ecosystem=Ecosystem.PYPI)
    assert req.version is None


def test_scan_request_empty_package_fails():
    with pytest.raises(ValidationError):
        ScanRequest(package="", ecosystem=Ecosystem.PYPI)


def test_scan_request_space_in_package_fails():
    with pytest.raises(ValidationError):
        ScanRequest(package="some package", ecosystem=Ecosystem.PYPI)


# ── ScanResult validation ─────────────────────────────────────────────────────

def _result(**overrides) -> ScanResult:
    defaults = dict(
        request=ScanRequest(package="pkg", ecosystem=Ecosystem.PYPI),
        findings=[],
        max_severity=Severity.NONE,
        decision=Decision(action=DecisionAction.ALLOW, reason="ok"),
    )
    defaults.update(overrides)
    return ScanResult(**defaults)


def test_scan_result_no_findings():
    r = _result()
    assert r.max_severity == Severity.NONE
    assert r.cache_hit is False


def test_scan_result_max_severity_consistent():
    f = _finding(severity=Severity.HIGH)
    r = _result(findings=[f], max_severity=Severity.HIGH)
    assert r.max_severity == Severity.HIGH


def test_scan_result_max_severity_too_low():
    f = _finding(severity=Severity.CRITICAL)
    with pytest.raises(ValidationError):
        _result(findings=[f], max_severity=Severity.HIGH)
