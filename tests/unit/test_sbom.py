"""Unit tests for the CycloneDX SBOM generator."""

from __future__ import annotations

import json
import re

from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.core.sbom import _SEVERITY_MAP, _purl, generate_sbom, generate_sbom_json

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_result(
    package: str = "requests",
    version: str | None = "2.31.0",
    ecosystem: Ecosystem = Ecosystem.PYPI,
    findings: list[Finding] | None = None,
    action: DecisionAction = DecisionAction.ALLOW,
    severity: Severity = Severity.NONE,
) -> ScanResult:
    return ScanResult(
        request=ScanRequest(package=package, version=version, ecosystem=ecosystem),
        findings=findings or [],
        max_severity=severity,
        decision=Decision(action=action, reason="test"),
    )


def _make_finding(
    rule_id: str = "CVE-2024-1234",
    severity: Severity = Severity.HIGH,
    cvss_score: float | None = 8.1,
    description: str = "Test finding",
    references: list[str] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test title",
        description=description,
        severity=severity,
        source="osv",
        cvss_score=cvss_score,
        remediation="Upgrade to 2.32.0",
        references=references or [],
    )


# ── _purl ─────────────────────────────────────────────────────────────────────


def test_purl_pypi_with_version() -> None:
    assert _purl("requests", "2.31.0", Ecosystem.PYPI) == "pkg:pypi/requests@2.31.0"


def test_purl_pypi_without_version() -> None:
    assert _purl("requests", None, Ecosystem.PYPI) == "pkg:pypi/requests"


def test_purl_pypi_normalises_underscores() -> None:
    assert _purl("my_package", "1.0.0", Ecosystem.PYPI) == "pkg:pypi/my-package@1.0.0"


def test_purl_pypi_lowercase() -> None:
    assert _purl("Django", "4.2.0", Ecosystem.PYPI) == "pkg:pypi/django@4.2.0"


def test_purl_npm_with_version() -> None:
    assert _purl("lodash", "4.17.21", Ecosystem.NPM) == "pkg:npm/lodash@4.17.21"


def test_purl_npm_without_version() -> None:
    assert _purl("lodash", None, Ecosystem.NPM) == "pkg:npm/lodash"


def test_purl_cargo_with_version() -> None:
    assert _purl("serde", "1.0.0", Ecosystem.CARGO) == "pkg:cargo/serde@1.0.0"


# ── _SEVERITY_MAP ─────────────────────────────────────────────────────────────


def test_severity_map_all_values_present() -> None:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"):
        assert sev in _SEVERITY_MAP


def test_severity_map_lowercase_values() -> None:
    for v in _SEVERITY_MAP.values():
        assert v == v.lower()


# ── generate_sbom structure ───────────────────────────────────────────────────


def test_sbom_top_level_fields() -> None:
    sbom = generate_sbom([_make_result()])
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert sbom["version"] == 1
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert "metadata" in sbom
    assert "components" in sbom


def test_sbom_serial_number_is_valid_uuid() -> None:
    sbom = generate_sbom([_make_result()])
    serial = sbom["serialNumber"]
    # urn:uuid:<uuid4>
    assert re.match(
        r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        serial,
    )


def test_sbom_serial_number_differs_per_call() -> None:
    s1 = generate_sbom([_make_result()])["serialNumber"]
    s2 = generate_sbom([_make_result()])["serialNumber"]
    assert s1 != s2


def test_sbom_metadata_timestamp_iso8601() -> None:
    sbom = generate_sbom([_make_result()])
    ts = sbom["metadata"]["timestamp"]
    assert "T" in ts
    assert ts.endswith("Z")


def test_sbom_metadata_tool_name() -> None:
    sbom = generate_sbom([_make_result()])
    tools = sbom["metadata"]["tools"]
    assert len(tools) == 1
    assert tools[0]["name"] == "agentshield"
    assert tools[0]["vendor"] == "AgentShield"


def test_sbom_metadata_source_path_included_when_given() -> None:
    sbom = generate_sbom([_make_result()], source_path="requirements.txt")
    assert sbom["metadata"]["component"]["name"] == "requirements.txt"
    assert sbom["metadata"]["component"]["type"] == "file"


def test_sbom_metadata_source_path_absent_when_none() -> None:
    sbom = generate_sbom([_make_result()])
    assert "component" not in sbom["metadata"]


# ── components ────────────────────────────────────────────────────────────────


def test_sbom_component_fields() -> None:
    sbom = generate_sbom([_make_result(package="requests", version="2.31.0")])
    assert len(sbom["components"]) == 1
    comp = sbom["components"][0]
    assert comp["type"] == "library"
    assert comp["name"] == "requests"
    assert comp["version"] == "2.31.0"
    assert comp["purl"] == "pkg:pypi/requests@2.31.0"
    assert comp["bom-ref"] == "pkg:pypi/requests@2.31.0"


def test_sbom_component_without_version() -> None:
    sbom = generate_sbom([_make_result(version=None)])
    comp = sbom["components"][0]
    assert "version" not in comp
    assert comp["purl"] == "pkg:pypi/requests"


def test_sbom_component_agentshield_properties() -> None:
    sbom = generate_sbom([_make_result(action=DecisionAction.BLOCK, severity=Severity.HIGH)])
    props = {p["name"]: p["value"] for p in sbom["components"][0]["properties"]}
    assert props["agentshield:decision"] == "BLOCK"
    assert props["agentshield:max_severity"] == "HIGH"


def test_sbom_multiple_components() -> None:
    results = [
        _make_result(package="requests", version="2.31.0"),
        _make_result(package="flask", version="3.0.0"),
        _make_result(package="numpy", version="1.26.0"),
    ]
    sbom = generate_sbom(results)
    assert len(sbom["components"]) == 3
    names = [c["name"] for c in sbom["components"]]
    assert names == ["requests", "flask", "numpy"]


def test_sbom_npm_component_purl() -> None:
    sbom = generate_sbom(
        [_make_result(package="lodash", version="4.17.21", ecosystem=Ecosystem.NPM)]
    )
    comp = sbom["components"][0]
    assert comp["purl"] == "pkg:npm/lodash@4.17.21"


def test_sbom_cargo_component_purl() -> None:
    sbom = generate_sbom(
        [_make_result(package="serde", version="1.0.0", ecosystem=Ecosystem.CARGO)]
    )
    assert sbom["components"][0]["purl"] == "pkg:cargo/serde@1.0.0"


# ── vulnerabilities ───────────────────────────────────────────────────────────


def test_sbom_no_vulnerabilities_section_when_clean() -> None:
    sbom = generate_sbom([_make_result()])
    assert "vulnerabilities" not in sbom


def test_sbom_vulnerability_fields() -> None:
    finding = _make_finding(rule_id="CVE-2024-1234", severity=Severity.HIGH, cvss_score=8.1)
    result = _make_result(findings=[finding], action=DecisionAction.BLOCK, severity=Severity.HIGH)
    sbom = generate_sbom([result])

    assert "vulnerabilities" in sbom
    vulns = sbom["vulnerabilities"]
    assert len(vulns) == 1
    v = vulns[0]
    assert v["id"] == "CVE-2024-1234"
    assert v["bom-ref"].startswith("vuln-CVE-2024-1234-")
    assert v["affects"][0]["ref"] == "pkg:pypi/requests@2.31.0"


def test_sbom_vulnerability_rating_with_cvss() -> None:
    finding = _make_finding(cvss_score=7.5, severity=Severity.HIGH)
    sbom = generate_sbom([_make_result(findings=[finding], severity=Severity.HIGH)])
    rating = sbom["vulnerabilities"][0]["ratings"][0]
    assert rating["score"] == 7.5
    assert rating["severity"] == "high"
    assert rating["method"] == "CVSSv3"


def test_sbom_vulnerability_rating_without_cvss() -> None:
    finding = _make_finding(cvss_score=None, severity=Severity.MEDIUM)
    sbom = generate_sbom([_make_result(findings=[finding], severity=Severity.MEDIUM)])
    rating = sbom["vulnerabilities"][0]["ratings"][0]
    assert rating["severity"] == "medium"
    assert "score" not in rating
    assert "method" not in rating


def test_sbom_vulnerability_references_included() -> None:
    finding = _make_finding(references=["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"])
    sbom = generate_sbom([_make_result(findings=[finding], severity=Severity.HIGH)])
    refs = sbom["vulnerabilities"][0]["references"]
    assert len(refs) == 1
    assert refs[0]["source"]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"


def test_sbom_duplicate_findings_deduplicated() -> None:
    finding = _make_finding()
    # Same package, same finding → should appear once
    result = _make_result(findings=[finding, finding], severity=Severity.HIGH)
    sbom = generate_sbom([result])
    assert len(sbom["vulnerabilities"]) == 1


def test_sbom_findings_across_multiple_packages() -> None:
    f1 = _make_finding(rule_id="CVE-2024-0001")
    f2 = _make_finding(rule_id="CVE-2024-0002")
    results = [
        _make_result(
            package="requests", findings=[f1], action=DecisionAction.BLOCK, severity=Severity.HIGH
        ),
        _make_result(
            package="flask", findings=[f2], action=DecisionAction.BLOCK, severity=Severity.HIGH
        ),
    ]
    sbom = generate_sbom(results)
    vuln_ids = {v["id"] for v in sbom["vulnerabilities"]}
    assert vuln_ids == {"CVE-2024-0001", "CVE-2024-0002"}


def test_sbom_empty_results() -> None:
    sbom = generate_sbom([])
    assert sbom["components"] == []
    assert "vulnerabilities" not in sbom


# ── generate_sbom_json ────────────────────────────────────────────────────────


def test_generate_sbom_json_is_valid_json() -> None:
    text = generate_sbom_json([_make_result()])
    parsed = json.loads(text)
    assert parsed["bomFormat"] == "CycloneDX"


def test_generate_sbom_json_pretty_printed() -> None:
    text = generate_sbom_json([_make_result()])
    # Pretty printing means the first line is "{" and next line is indented
    lines = text.splitlines()
    assert lines[0] == "{"
    assert lines[1].startswith("  ")


def test_generate_sbom_json_round_trip() -> None:
    results = [
        _make_result(package="requests", version="2.31.0"),
        _make_result(
            package="vuln-pkg",
            version="1.0.0",
            findings=[_make_finding()],
            action=DecisionAction.BLOCK,
            severity=Severity.HIGH,
        ),
    ]
    text = generate_sbom_json(results, source_path="requirements.txt")
    sbom = json.loads(text)
    assert len(sbom["components"]) == 2
    assert len(sbom["vulnerabilities"]) == 1
    assert sbom["metadata"]["component"]["name"] == "requirements.txt"
