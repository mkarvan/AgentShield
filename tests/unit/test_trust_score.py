"""Unit tests for analyzers/trust_score.py."""

from __future__ import annotations

import httpx
import respx

from agentshield.analyzers.trust_score import (
    TrustScoreResult,
    _score_to_label,
    compute_trust_score,
)
from agentshield.core.models import Ecosystem, ScanRequest, Severity

# ── _score_to_label ───────────────────────────────────────────────────────────


def test_label_high_trust() -> None:
    assert _score_to_label(100) == "high-trust"
    assert _score_to_label(80) == "high-trust"


def test_label_moderate() -> None:
    assert _score_to_label(79) == "moderate"
    assert _score_to_label(50) == "moderate"


def test_label_low_trust() -> None:
    assert _score_to_label(49) == "low-trust"
    assert _score_to_label(20) == "low-trust"


def test_label_suspicious() -> None:
    assert _score_to_label(19) == "suspicious"
    assert _score_to_label(0) == "suspicious"


# ── TrustScoreResult.to_finding ───────────────────────────────────────────────


def _pypi_req(name: str = "requests") -> ScanRequest:
    return ScanRequest(package=name, ecosystem=Ecosystem.PYPI)


def test_to_finding_returns_none_for_high_trust() -> None:
    ts = TrustScoreResult(score=80, label="high-trust")
    assert ts.to_finding(_pypi_req()) is None


def test_to_finding_returns_none_for_moderate() -> None:
    ts = TrustScoreResult(score=55, label="moderate")
    assert ts.to_finding(_pypi_req()) is None


def test_to_finding_high_severity_for_low_trust() -> None:
    ts = TrustScoreResult(score=30, label="low-trust", signals={"age_days": 30, "release_count": 1})
    finding = ts.to_finding(_pypi_req("shady-pkg"))
    assert finding is not None
    assert finding.rule_id == "T5.1"
    assert finding.severity == Severity.HIGH
    assert "shady-pkg" in finding.description


def test_to_finding_critical_for_suspicious() -> None:
    ts = TrustScoreResult(score=5, label="suspicious", signals={"age_days": 5, "release_count": 0})
    finding = ts.to_finding(_pypi_req())
    assert finding is not None
    assert finding.severity == Severity.CRITICAL


def test_to_finding_boundary_49() -> None:
    ts = TrustScoreResult(
        score=49, label="low-trust", signals={"age_days": 100, "release_count": 2}
    )
    finding = ts.to_finding(_pypi_req())
    assert finding is not None


def test_to_finding_boundary_50() -> None:
    ts = TrustScoreResult(score=50, label="moderate")
    assert ts.to_finding(_pypi_req()) is None


# ── compute_trust_score — no data path ────────────────────────────────────────


@respx.mock
async def test_compute_trust_score_returns_neutral_on_404() -> None:
    respx.get("https://pypi.org/pypi/unknown-pkg-xyz/json").mock(return_value=httpx.Response(404))
    req = ScanRequest(package="unknown-pkg-xyz", ecosystem=Ecosystem.PYPI)
    result = await compute_trust_score(req)
    assert isinstance(result.score, int)
    assert 0 <= result.score <= 100
    assert result.label in ("high-trust", "moderate", "low-trust", "suspicious")


@respx.mock
async def test_compute_trust_score_pypi_happy_path() -> None:
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {
                    "summary": "Python HTTP for Humans",
                    "author": "Kenneth Reitz",
                    "home_page": "https://requests.readthedocs.io",
                },
                "urls": [{"upload_time_iso_8601": "2018-06-15T00:00:00+00:00"}],
                "releases": {str(i): [] for i in range(50)},
            },
        )
    )
    respx.get("https://pypistats.org/api/packages/requests/recent").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"last_month": 5_000_000}},
        )
    )
    req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)
    result = await compute_trust_score(req)
    assert result.score >= 50
    assert result.label in ("high-trust", "moderate")
    assert "monthly_downloads" in result.signals


@respx.mock
async def test_compute_trust_score_npm_happy_path() -> None:
    respx.get("https://registry.npmjs.org/lodash").mock(
        return_value=httpx.Response(
            200,
            json={
                "time": {"created": "2012-04-23T00:00:00.000Z"},
                "versions": {str(i): {} for i in range(80)},
                "maintainers": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
            },
        )
    )
    respx.get("https://api.npmjs.org/downloads/point/last-month/lodash").mock(
        return_value=httpx.Response(
            200,
            json={"downloads": 200_000_000},
        )
    )
    req = ScanRequest(package="lodash", ecosystem=Ecosystem.NPM)
    result = await compute_trust_score(req)
    assert result.score >= 60
    assert result.signals.get("maintainer_count") == 3


@respx.mock
async def test_compute_trust_score_cargo_happy_path() -> None:
    respx.get("https://crates.io/api/v1/crates/serde").mock(
        return_value=httpx.Response(
            200,
            json={
                "crate": {
                    "created_at": "2015-01-01T00:00:00+00:00",
                    "downloads": 2_000_000,
                },
                "versions": [{"num": str(i)} for i in range(60)],
            },
        )
    )
    req = ScanRequest(package="serde", ecosystem=Ecosystem.CARGO)
    result = await compute_trust_score(req)
    assert result.score >= 60
    assert result.signals.get("total_downloads") == 2_000_000


@respx.mock
async def test_compute_trust_score_network_error_returns_neutral() -> None:
    respx.get("https://pypi.org/pypi/any-pkg/json").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    req = ScanRequest(package="any-pkg", ecosystem=Ecosystem.PYPI)
    result = await compute_trust_score(req)
    assert result.score == 50
    assert result.label == "moderate"


@respx.mock
async def test_compute_trust_score_pypistats_failure_does_not_crash() -> None:
    respx.get("https://pypi.org/pypi/pkg/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {"summary": "A package", "author": "A", "home_page": "http://x.com"},
                "urls": [{"upload_time_iso_8601": "2020-01-01T00:00:00+00:00"}],
                "releases": {"1.0.0": []},
            },
        )
    )
    respx.get("https://pypistats.org/api/packages/pkg/recent").mock(
        return_value=httpx.Response(500)
    )
    req = ScanRequest(package="pkg", ecosystem=Ecosystem.PYPI)
    result = await compute_trust_score(req)
    assert isinstance(result.score, int)


@respx.mock
async def test_pypi_age_uses_earliest_release_not_latest_upload() -> None:
    """Regression: age was measured from the *latest* release's upload time, so
    a 10-year-old package that shipped yesterday scored like a brand-new one
    (and abandonware got full age points). Age must come from the earliest
    upload across all releases."""
    respx.get("https://pypi.org/pypi/old-but-active/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {},
                # Latest release uploaded very recently…
                "urls": [{"upload_time_iso_8601": "2026-06-30T00:00:00+00:00"}],
                # …but the first release is over a decade old.
                "releases": {
                    "0.1.0": [{"upload_time_iso_8601": "2012-01-01T00:00:00+00:00"}],
                    "9.0.0": [{"upload_time_iso_8601": "2026-06-30T00:00:00+00:00"}],
                },
            },
        )
    )
    respx.get("https://pypistats.org/api/packages/old-but-active/recent").mock(
        return_value=httpx.Response(200, json={"data": {"last_month": 10}})
    )
    req = ScanRequest(package="old-but-active", ecosystem=Ecosystem.PYPI)
    result = await compute_trust_score(req)
    # >10 years old → far beyond the 30-month cap → full age signal.
    assert result.signals["age_days"] > 3000


def test_earliest_upload_falls_back_to_urls_when_releases_have_no_files() -> None:
    from agentshield.analyzers.trust_score import _earliest_upload

    dt = _earliest_upload(
        {"1.0": [], "2.0": []},
        fallback_urls=[{"upload_time_iso_8601": "2020-01-01T00:00:00+00:00"}],
    )
    assert dt is not None and dt.year == 2020


def test_earliest_upload_none_when_no_timestamps() -> None:
    from agentshield.analyzers.trust_score import _earliest_upload

    assert _earliest_upload({}, fallback_urls=[]) is None
    assert _earliest_upload({"1.0": [{}]}, fallback_urls=[{}]) is None


@respx.mock
async def test_new_package_scores_lower_than_established() -> None:
    respx.get("https://pypi.org/pypi/brand-new/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {},
                "urls": [{"upload_time_iso_8601": "2024-06-01T00:00:00+00:00"}],
                "releases": {"0.1.0": []},
            },
        )
    )
    respx.get("https://pypistats.org/api/packages/brand-new/recent").mock(
        return_value=httpx.Response(200, json={"data": {"last_month": 10}})
    )
    respx.get("https://pypi.org/pypi/requests/json").mock(
        return_value=httpx.Response(
            200,
            json={
                "info": {
                    "summary": "A popular library",
                    "author": "Author",
                    "home_page": "http://example.com",
                },
                "urls": [{"upload_time_iso_8601": "2011-02-14T00:00:00+00:00"}],
                "releases": {str(i): [] for i in range(100)},
            },
        )
    )
    respx.get("https://pypistats.org/api/packages/requests/recent").mock(
        return_value=httpx.Response(200, json={"data": {"last_month": 5_000_000}})
    )

    new_req = ScanRequest(package="brand-new", ecosystem=Ecosystem.PYPI)
    est_req = ScanRequest(package="requests", ecosystem=Ecosystem.PYPI)

    new_result = await compute_trust_score(new_req)
    est_result = await compute_trust_score(est_req)

    assert est_result.score > new_result.score
