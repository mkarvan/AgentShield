"""Unit tests for the OSV bulk cache warm-up module."""
from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest
import respx
from httpx import Response

from agentshield.core.models import Ecosystem
from agentshield.databases.warm import (
    _extract_affected_versions,
    _extract_severity,
    _parse_advisory,
    _severity_from_score,
    warm_cache,
)


def _make_zip(advisories: list[dict]) -> bytes:
    """Build an in-memory zip with one JSON file per advisory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i, adv in enumerate(advisories):
            zf.writestr(f"{adv.get('id', f'ADV-{i}')}.json", json.dumps(adv))
    return buf.getvalue()


def _make_adv(
    adv_id: str = "PYSEC-2024-001",
    pkg_name: str = "requests",
    adv_type: str | None = None,
    severity: str = "HIGH",
    ecosystem: str = "PyPI",
) -> dict:
    adv: dict = {
        "id": adv_id,
        "summary": f"Advisory {adv_id}",
        "details": f"Details for {adv_id}",
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "2.29.0"}],
                    }
                ],
            }
        ],
        "database_specific": {"severity": severity},
        "severity": [],
    }
    if adv_type:
        adv["database_specific"]["type"] = adv_type
    return adv


# ── _severity_from_score ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (9.5, "CRITICAL"),
    (9.0, "CRITICAL"),
    (8.9, "HIGH"),
    (7.0, "HIGH"),
    (6.9, "MEDIUM"),
    (4.0, "MEDIUM"),
    (3.9, "LOW"),
    (0.1, "LOW"),
    (0.0, "INFO"),
])
def test_severity_from_score(score: float, expected: str):
    assert _severity_from_score(score) == expected


# ── _extract_severity ─────────────────────────────────────────────────────────────

def test_extract_severity_from_database_specific():
    adv = {"database_specific": {"severity": "CRITICAL"}, "severity": []}
    sev, score = _extract_severity(adv)
    assert sev == "CRITICAL"
    assert score is None


def test_extract_severity_moderate_maps_to_medium():
    adv = {"database_specific": {"severity": "MODERATE"}, "severity": []}
    sev, _ = _extract_severity(adv)
    assert sev == "MEDIUM"


def test_extract_severity_from_cvss_vector():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL
    adv = {
        "database_specific": {},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    sev, score = _extract_severity(adv)
    assert sev == "CRITICAL"
    assert score is not None and score >= 9.0


def test_extract_severity_fallback_to_medium():
    adv = {"database_specific": {}, "severity": []}
    sev, score = _extract_severity(adv)
    assert sev == "MEDIUM"
    assert score is None


# ── _extract_affected_versions ────────────────────────────────────────────────────

def test_extract_affected_versions():
    adv = {
        "affected": [
            {
                "ranges": [
                    {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
                ]
            }
        ]
    }
    result = _extract_affected_versions(adv)
    parsed = json.loads(result)
    assert len(parsed) == 1
    assert parsed[0]["type"] == "SEMVER"


def test_extract_affected_versions_empty():
    result = _extract_affected_versions({"affected": []})
    assert json.loads(result) == []


# ── _parse_advisory ─────────────────────────────────────────────────────────────

def test_parse_advisory_cve_row():
    adv = _make_adv(severity="HIGH")
    cve_rows: list = []
    mal_rows: list = []
    _parse_advisory(adv, Ecosystem.PYPI, cve_rows, mal_rows)
    assert len(cve_rows) == 1
    assert len(mal_rows) == 0
    row = cve_rows[0]
    assert row[0] == "PYSEC-2024-001"  # id
    assert row[1] == "requests"  # package (lowercased)
    assert row[4] == "HIGH"  # severity


def test_parse_advisory_malicious_row():
    adv = _make_adv(adv_type="MALICIOUS")
    cve_rows: list = []
    mal_rows: list = []
    _parse_advisory(adv, Ecosystem.PYPI, cve_rows, mal_rows)
    assert len(mal_rows) == 1
    assert len(cve_rows) == 0
    assert mal_rows[0][0] == "requests"
    assert mal_rows[0][3] == "osv_malicious"


def test_parse_advisory_skips_low_severity():
    adv = _make_adv(severity="LOW")
    cve_rows: list = []
    mal_rows: list = []
    _parse_advisory(adv, Ecosystem.PYPI, cve_rows, mal_rows)
    assert len(cve_rows) == 0  # LOW is below the MEDIUM+ threshold


def test_parse_advisory_skips_wrong_ecosystem():
    adv = _make_adv(severity="CRITICAL", ecosystem="npm")
    cve_rows: list = []
    mal_rows: list = []
    _parse_advisory(adv, Ecosystem.PYPI, cve_rows, mal_rows)
    assert len(cve_rows) == 0  # Package is in npm, not PyPI


def test_parse_advisory_no_package_skips():
    adv = {
        "id": "ADV-001",
        "affected": [],
        "database_specific": {"severity": "CRITICAL"},
        "severity": [],
    }
    cve_rows: list = []
    mal_rows: list = []
    _parse_advisory(adv, Ecosystem.PYPI, cve_rows, mal_rows)
    assert len(cve_rows) == 0


# ── warm_cache ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_warm_cache_populates_db(tmp_path: Path):
    db_path = tmp_path / "test.db"

    advisories = [
        _make_adv("PYSEC-2024-001", "requests", severity="HIGH"),
        _make_adv("PYSEC-2024-002", "flask", severity="CRITICAL"),
        _make_adv("MAL-2024-001", "evil-pkg", adv_type="MALICIOUS"),
    ]
    zip_bytes = _make_zip(advisories)

    respx.get("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip").mock(
        return_value=Response(200, content=zip_bytes)
    )

    stats = await warm_cache(db_path, ecosystems=[Ecosystem.PYPI])

    assert stats.cve_rows_inserted >= 2
    assert stats.malicious_rows_inserted >= 1
    assert "pypi" in stats.ecosystems_processed
    assert stats.advisories_scanned >= 3


@pytest.mark.asyncio
@respx.mock
async def test_warm_cache_handles_http_error(tmp_path: Path):
    db_path = tmp_path / "test.db"

    respx.get("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip").mock(
        return_value=Response(503)
    )

    stats = await warm_cache(db_path, ecosystems=[Ecosystem.PYPI])
    assert len(stats.errors) == 1
    assert "pypi" not in stats.ecosystems_processed


@pytest.mark.asyncio
@respx.mock
async def test_warm_cache_calls_progress_callback(tmp_path: Path):
    db_path = tmp_path / "test.db"

    respx.get("https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip").mock(
        return_value=Response(200, content=_make_zip([_make_adv()]))
    )

    progress_calls: list[tuple] = []

    def on_progress(eco: str, phase: str, count: int) -> None:
        progress_calls.append((eco, phase, count))

    await warm_cache(db_path, ecosystems=[Ecosystem.PYPI], progress_callback=on_progress)
    phases = [p for _, p, _ in progress_calls]
    assert "downloading" in phases
    assert "parsing" in phases or "done" in phases


@pytest.mark.asyncio
@respx.mock
async def test_warm_cache_multiple_ecosystems(tmp_path: Path):
    db_path = tmp_path / "test.db"

    for eco_name in ["PyPI", "npm", "crates.io"]:
        advisories = [_make_adv(f"ADV-{eco_name}-001", "pkg", ecosystem=eco_name)]
        respx.get(
            f"https://osv-vulnerabilities.storage.googleapis.com/{eco_name}/all.zip"
        ).mock(return_value=Response(200, content=_make_zip(advisories)))

    stats = await warm_cache(db_path, ecosystems=list(Ecosystem))
    assert len(stats.ecosystems_processed) == 3
