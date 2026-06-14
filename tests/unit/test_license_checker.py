"""Unit tests for license_checker.py — all HTTP calls mocked via respx."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from agentshield.analyzers.license_checker import (
    LicenseChecker,
    normalize_spdx,
)
from agentshield.core.config import LicensePolicy
from agentshield.core.models import Ecosystem, ScanRequest, Severity

PYPI_BASE = "https://pypi.org/pypi"
NPM_BASE = "https://registry.npmjs.org"
CRATES_BASE = "https://crates.io/api/v1/crates"


# ── helpers ───────────────────────────────────────────────────────────────────


def _req(
    pkg: str = "testpkg",
    ecosystem: Ecosystem = Ecosystem.PYPI,
    version: str | None = None,
) -> ScanRequest:
    return ScanRequest(package=pkg, ecosystem=ecosystem, version=version)


def _policy(**kwargs: object) -> LicensePolicy:
    return LicensePolicy(**kwargs)  # type: ignore[arg-type]


def _pypi_resp(
    license_str: str | None = None,
    classifiers: list[str] | None = None,
) -> Response:
    return Response(
        200,
        json={
            "info": {
                "license": license_str or "",
                "classifiers": classifiers or [],
            }
        },
    )


def _npm_resp(license_field: object = "MIT") -> Response:
    return Response(200, json={"license": license_field})


def _crates_meta_resp(license_str: str = "MIT OR Apache-2.0") -> Response:
    return Response(200, json={"crate": {"license": license_str}})


def _crates_ver_resp(license_str: str = "MIT") -> Response:
    return Response(200, json={"version": {"license": license_str}})


# ── normalize_spdx ────────────────────────────────────────────────────────────


def test_normalize_spdx_already_spdx():
    assert normalize_spdx("MIT") == ["MIT"]


def test_normalize_spdx_already_spdx_apache():
    assert normalize_spdx("Apache-2.0") == ["Apache-2.0"]


def test_normalize_spdx_alias_gplv2():
    assert normalize_spdx("GPLv2") == ["GPL-2.0-only"]


def test_normalize_spdx_alias_gplv3():
    assert normalize_spdx("GPLv3") == ["GPL-3.0-only"]


def test_normalize_spdx_alias_mit_license():
    assert normalize_spdx("MIT License") == ["MIT"]


def test_normalize_spdx_alias_apache_2():
    assert normalize_spdx("Apache 2.0") == ["Apache-2.0"]


def test_normalize_spdx_alias_agpl():
    assert normalize_spdx("AGPLv3") == ["AGPL-3.0-only"]


def test_normalize_spdx_or_expression():
    result = normalize_spdx("MIT OR Apache-2.0")
    assert "MIT" in result
    assert "Apache-2.0" in result
    assert len(result) == 2


def test_normalize_spdx_cargo_slash_separator():
    result = normalize_spdx("MIT/Apache-2.0")
    assert "MIT" in result
    assert "Apache-2.0" in result


def test_normalize_spdx_empty_string():
    assert normalize_spdx("") == []


def test_normalize_spdx_unknown():
    assert normalize_spdx("unknown") == []


def test_normalize_spdx_see_license():
    assert normalize_spdx("SEE LICENSE IN LICENSE") == []


def test_normalize_spdx_proprietary():
    assert normalize_spdx("Proprietary") == []


def test_normalize_spdx_and_expression():
    result = normalize_spdx("GPL-2.0-only AND MIT")
    assert "GPL-2.0-only" in result
    assert "MIT" in result


# ── disabled mode ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_disabled_mode_returns_empty():
    checker = LicenseChecker(_policy(mode="disabled"))
    findings = await checker.check(_req())
    assert findings == []


# ── denylist mode — PyPI ──────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_pypi_gpl_flagged_in_denylist_mode():
    respx.get(f"{PYPI_BASE}/gplpkg/json").mock(return_value=_pypi_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("gplpkg"))
    assert len(findings) == 1
    assert findings[0].rule_id == "L1.1"
    assert findings[0].severity == Severity.CRITICAL
    assert "GPL-3.0-only" in findings[0].title


@pytest.mark.asyncio
@respx.mock
async def test_pypi_agpl_flagged_critical():
    respx.get(f"{PYPI_BASE}/agplpkg/json").mock(return_value=_pypi_resp("AGPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("agplpkg"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
@respx.mock
async def test_pypi_mit_not_flagged_in_denylist_mode():
    respx.get(f"{PYPI_BASE}/mitpkg/json").mock(return_value=_pypi_resp("MIT"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("mitpkg"))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_pypi_classifiers_take_precedence_over_info_license():
    # Classifier says GPL, info.license says "MIT" — classifier wins.
    respx.get(f"{PYPI_BASE}/mixedpkg/json").mock(
        return_value=_pypi_resp(
            license_str="MIT",
            classifiers=["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"],
        )
    )
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("mixedpkg"))
    assert len(findings) == 1
    assert "GPL-3.0-only" in findings[0].title


@pytest.mark.asyncio
@respx.mock
async def test_pypi_mit_classifier_not_flagged():
    respx.get(f"{PYPI_BASE}/safepkg/json").mock(
        return_value=_pypi_resp(classifiers=["License :: OSI Approved :: MIT License"])
    )
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("safepkg"))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_pypi_versioned_url_used_when_version_given():
    respx.get(f"{PYPI_BASE}/mypkg/1.2.3/json").mock(return_value=_pypi_resp("GPL-2.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("mypkg", version="1.2.3"))
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_pypi_eupl_flagged_as_high():
    respx.get(f"{PYPI_BASE}/eulpkg/json").mock(return_value=_pypi_resp("EUPL-1.1"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("eulpkg"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


# ── denylist mode — npm ───────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_npm_gpl_flagged():
    respx.get(f"{NPM_BASE}/gplmod/latest").mock(return_value=_npm_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("gplmod", ecosystem=Ecosystem.NPM))
    assert len(findings) == 1
    assert findings[0].rule_id == "L1.1"


@pytest.mark.asyncio
@respx.mock
async def test_npm_mit_not_flagged():
    respx.get(f"{NPM_BASE}/safemod/latest").mock(return_value=_npm_resp("MIT"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("safemod", ecosystem=Ecosystem.NPM))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_npm_license_dict_format():
    # npm sometimes returns {"license": {"type": "MIT"}}
    respx.get(f"{NPM_BASE}/dictmod/latest").mock(return_value=_npm_resp({"type": "MIT"}))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("dictmod", ecosystem=Ecosystem.NPM))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_npm_license_dict_gpl():
    respx.get(f"{NPM_BASE}/dictgpl/latest").mock(return_value=_npm_resp({"type": "GPL-3.0-only"}))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("dictgpl", ecosystem=Ecosystem.NPM))
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_npm_versioned_url():
    respx.get(f"{NPM_BASE}/verpkg/2.0.0").mock(return_value=_npm_resp("GPL-2.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("verpkg", ecosystem=Ecosystem.NPM, version="2.0.0"))
    assert len(findings) == 1


# ── denylist mode — Cargo ─────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_cargo_mit_apache_not_flagged():
    respx.get(f"{CRATES_BASE}/safecrate").mock(return_value=_crates_meta_resp("MIT OR Apache-2.0"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("safecrate", ecosystem=Ecosystem.CARGO))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_cargo_gpl_flagged():
    respx.get(f"{CRATES_BASE}/gplcrate").mock(return_value=_crates_meta_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("gplcrate", ecosystem=Ecosystem.CARGO))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
@respx.mock
async def test_cargo_versioned_uses_version_endpoint():
    respx.get(f"{CRATES_BASE}/serde/1.0.0").mock(return_value=_crates_ver_resp("MIT OR Apache-2.0"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("serde", ecosystem=Ecosystem.CARGO, version="1.0.0"))
    assert findings == []


# ── allowlist mode ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_allowlist_mode_mit_in_allowed_not_flagged():
    respx.get(f"{PYPI_BASE}/mypkg/json").mock(return_value=_pypi_resp("MIT"))
    checker = LicenseChecker(_policy(mode="allowlist", allowed=["MIT", "Apache-2.0"]))
    findings = await checker.check(_req("mypkg"))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_allowlist_mode_unlisted_license_flagged():
    respx.get(f"{PYPI_BASE}/mypkg/json").mock(return_value=_pypi_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="allowlist", allowed=["MIT", "Apache-2.0"]))
    findings = await checker.check(_req("mypkg"))
    assert len(findings) == 1
    assert "not in allowlist" in findings[0].title


@pytest.mark.asyncio
@respx.mock
async def test_allowlist_mode_case_insensitive():
    respx.get(f"{PYPI_BASE}/mypkg/json").mock(return_value=_pypi_resp("mit"))
    checker = LicenseChecker(_policy(mode="allowlist", allowed=["MIT"]))
    findings = await checker.check(_req("mypkg"))
    assert findings == []


# ── permissive-only mode ──────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_permissive_only_flags_gpl():
    respx.get(f"{PYPI_BASE}/gplpkg/json").mock(return_value=_pypi_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="permissive-only"))
    findings = await checker.check(_req("gplpkg"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
@respx.mock
async def test_permissive_only_flags_lgpl():
    respx.get(f"{PYPI_BASE}/lgplpkg/json").mock(return_value=_pypi_resp("LGPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="permissive-only"))
    findings = await checker.check(_req("lgplpkg"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
@respx.mock
async def test_permissive_only_allows_mit():
    respx.get(f"{PYPI_BASE}/mitpkg/json").mock(return_value=_pypi_resp("MIT"))
    checker = LicenseChecker(_policy(mode="permissive-only"))
    findings = await checker.check(_req("mitpkg"))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_permissive_only_allows_apache():
    respx.get(f"{PYPI_BASE}/apachepkg/json").mock(return_value=_pypi_resp("Apache-2.0"))
    checker = LicenseChecker(_policy(mode="permissive-only"))
    findings = await checker.check(_req("apachepkg"))
    assert findings == []


# ── error handling ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_api_error_returns_empty_not_raises():
    respx.get(f"{PYPI_BASE}/brokenpkg/json").mock(return_value=Response(500))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("brokenkg"))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_missing_license_field_returns_empty():
    respx.get(f"{PYPI_BASE}/nolicpkg/json").mock(
        return_value=Response(200, json={"info": {"license": "", "classifiers": []}})
    )
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("nolicpkg"))
    assert findings == []


@pytest.mark.asyncio
@respx.mock
async def test_unknown_license_string_returns_empty_in_denylist():
    # "unknown" is not in the denied list, so it should not be flagged.
    respx.get(f"{PYPI_BASE}/weirdpkg/json").mock(return_value=_pypi_resp("unknown"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("weirdpkg"))
    assert findings == []


# ── finding shape ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_finding_rule_id_is_l1_1():
    respx.get(f"{PYPI_BASE}/gplpkg/json").mock(return_value=_pypi_resp("GPL-2.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("gplpkg"))
    assert findings[0].rule_id == "L1.1"


@pytest.mark.asyncio
@respx.mock
async def test_finding_source_is_license_checker():
    respx.get(f"{PYPI_BASE}/gplpkg/json").mock(return_value=_pypi_resp("GPL-2.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("gplpkg"))
    assert findings[0].source == "license_checker"


@pytest.mark.asyncio
@respx.mock
async def test_finding_has_spdx_id_in_metadata():
    respx.get(f"{PYPI_BASE}/gplpkg/json").mock(return_value=_pypi_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("gplpkg"))
    assert findings[0].metadata["spdx_id"] == "GPL-3.0-only"


@pytest.mark.asyncio
@respx.mock
async def test_finding_has_spdx_reference_url():
    respx.get(f"{PYPI_BASE}/gplpkg/json").mock(return_value=_pypi_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("gplpkg"))
    assert any("spdx.org" in ref for ref in findings[0].references)


# ── custom denied list ────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_custom_denied_list_flagged():
    respx.get(f"{PYPI_BASE}/custpkg/json").mock(return_value=_pypi_resp("MIT"))
    checker = LicenseChecker(_policy(mode="denylist", denied=["MIT"]))
    findings = await checker.check(_req("custpkg"))
    assert len(findings) == 1


@pytest.mark.asyncio
@respx.mock
async def test_custom_denied_list_gpl_not_flagged_when_not_in_list():
    # If user sets denied=["MIT"], GPL should not be flagged.
    respx.get(f"{PYPI_BASE}/gplpkg/json").mock(return_value=_pypi_resp("GPL-3.0-only"))
    checker = LicenseChecker(_policy(mode="denylist", denied=["MIT"]))
    findings = await checker.check(_req("gplpkg"))
    assert findings == []


# ── GPL alias normalization in denylist ───────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_gpl_alias_normalized_and_flagged():
    # PyPI info.license field often contains "GPLv2" instead of "GPL-2.0-only".
    respx.get(f"{PYPI_BASE}/aliaspkg/json").mock(return_value=_pypi_resp("GPLv2"))
    checker = LicenseChecker(_policy(mode="denylist"))
    findings = await checker.check(_req("aliaspkg"))
    assert len(findings) == 1
    assert findings[0].metadata["spdx_id"] == "GPL-2.0-only"
