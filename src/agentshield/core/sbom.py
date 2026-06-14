"""CycloneDX v1.4 SBOM generator for AgentShield scan results.

Produces a Software Bill of Materials that lists all scanned packages as
components and annotates each component with AgentShield's decision and
severity rating.  Known vulnerabilities (findings with CVE-style rule IDs)
are emitted in the ``vulnerabilities`` section so downstream tools can
correlate them.

Usage::

    from agentshield.core.sbom import generate_sbom_json
    json_text = generate_sbom_json(file_result.results, source_path="requirements.txt")
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import Any

from agentshield.core.models import Ecosystem, ScanResult

try:
    _AGENTSHIELD_VERSION = _pkg_version("agentshield")
except PackageNotFoundError:
    _AGENTSHIELD_VERSION = "0.0.0-dev"
_CDX_SPEC = "1.4"

# CycloneDX severity strings (lowercase)
_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
    "NONE": "none",
}

# PURL ecosystem identifiers
_ECO_PURL: dict[Ecosystem, str] = {
    Ecosystem.PYPI: "pypi",
    Ecosystem.NPM: "npm",
    Ecosystem.CARGO: "cargo",
}


def _purl(name: str, version: str | None, ecosystem: Ecosystem) -> str:
    """Return a Package URL (PURL) for the given package."""
    eco = _ECO_PURL[ecosystem]
    # PyPI normalises dashes/underscores; keep lowercase for both
    name_norm = name.lower().replace("_", "-") if ecosystem == Ecosystem.PYPI else name
    if version:
        return f"pkg:{eco}/{name_norm}@{version}"
    return f"pkg:{eco}/{name_norm}"


def generate_sbom(
    results: list[ScanResult],
    source_path: str | None = None,
) -> dict[str, Any]:
    """Generate a CycloneDX v1.4 SBOM dict from a list of scan results.

    Args:
        results: Per-package ScanResult objects (e.g. from ``FileScanResult.results``).
        source_path: Optional path to the scanned manifest file, recorded in
                     the SBOM ``metadata.component`` field.

    Returns:
        A dict ready to serialize to JSON (use :func:`generate_sbom_json`).
    """
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    components: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []
    seen_vuln_keys: set[str] = set()

    for result in results:
        req = result.request
        pkg_purl = _purl(req.package, req.version, req.ecosystem)

        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": pkg_purl,
            "name": req.package,
            "purl": pkg_purl,
            "properties": [
                {"name": "agentshield:decision", "value": result.decision.action.value},
                {"name": "agentshield:max_severity", "value": result.max_severity.value},
            ],
        }
        if req.version:
            component["version"] = req.version
        components.append(component)

        # Emit findings as CycloneDX vulnerabilities
        for finding in result.findings:
            vuln_key = f"{finding.rule_id}::{pkg_purl}"
            if vuln_key in seen_vuln_keys:
                continue
            seen_vuln_keys.add(vuln_key)

            ratings: list[dict[str, Any]] = []
            if finding.cvss_score is not None:
                ratings.append(
                    {
                        "severity": _SEVERITY_MAP.get(finding.severity.value, "unknown"),
                        "score": finding.cvss_score,
                        "method": "CVSSv3",
                    }
                )
            else:
                ratings.append({"severity": _SEVERITY_MAP.get(finding.severity.value, "unknown")})

            vuln: dict[str, Any] = {
                "id": finding.rule_id,
                "bom-ref": f"vuln-{finding.rule_id}-{req.package}",
                "description": finding.description or finding.title,
                "ratings": ratings,
                "affects": [{"ref": pkg_purl}],
            }

            if finding.references:
                vuln["references"] = [
                    {"id": ref, "source": {"url": ref}} for ref in finding.references
                ]

            vulnerabilities.append(vuln)

    metadata: dict[str, Any] = {
        "timestamp": now,
        "tools": [
            {
                "vendor": "AgentShield",
                "name": "agentshield",
                "version": _AGENTSHIELD_VERSION,
            }
        ],
    }
    if source_path:
        metadata["component"] = {"type": "file", "name": source_path}

    sbom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _CDX_SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if vulnerabilities:
        sbom["vulnerabilities"] = vulnerabilities

    return sbom


def generate_sbom_json(
    results: list[ScanResult],
    source_path: str | None = None,
) -> str:
    """Generate a CycloneDX v1.4 SBOM as a pretty-printed JSON string."""
    return json.dumps(generate_sbom(results, source_path), indent=2)
