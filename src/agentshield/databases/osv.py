from __future__ import annotations

import math

import httpx

from agentshield.core.models import Ecosystem, Finding, ScanRequest, Severity

OSV_API = "https://api.osv.dev/v1/query"

_ECOSYSTEM_MAP = {
    Ecosystem.PYPI: "PyPI",
    Ecosystem.NPM: "npm",
    Ecosystem.CARGO: "crates.io",
}

# OSV uses MODERATE; NVD uses MEDIUM — normalise both
_SEVERITY_RATING_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "NONE": Severity.INFO,
}


class OSVClient:
    async def scan(self, request: ScanRequest) -> list[Finding]:
        payload: dict = {
            "package": {
                "name": request.package,
                "ecosystem": _ECOSYSTEM_MAP[request.ecosystem],
            }
        }
        if request.version:
            payload["version"] = request.version

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(OSV_API, json=payload)
            resp.raise_for_status()
            data = resp.json()

        return [_vuln_to_finding(v) for v in data.get("vulns", [])]


def _vuln_to_finding(vuln: dict) -> Finding:
    severity, cvss_score = _extract_severity(vuln)

    vuln_type = vuln.get("database_specific", {}).get("type", "")
    if vuln_type == "MALICIOUS":
        severity = Severity.CRITICAL
        rule_id = "T1.1"
    else:
        rule_id = vuln.get("id", "UNKNOWN")

    return Finding(
        rule_id=rule_id,
        title=vuln.get("summary", "Unknown vulnerability"),
        description=vuln.get("details", ""),
        severity=severity,
        source="osv",
        references=[r.get("url", "") for r in vuln.get("references", []) if r.get("url")],
        cvss_score=cvss_score,
        remediation=_extract_remediation(vuln),
    )


def _extract_severity(vuln: dict) -> tuple[Severity, float | None]:
    """Return (severity, cvss_score) for an OSV vuln object."""
    cvss_score: float | None = None
    severity = Severity.MEDIUM  # safe default

    # 1. database_specific.severity is the most reliable field for OSV entries
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    if db_sev:
        severity = _SEVERITY_RATING_MAP.get(db_sev.upper(), Severity.MEDIUM)

    # 2. Walk severity[] array for CVSS vector — extract numeric base score
    for sev_entry in vuln.get("severity", []):
        if sev_entry.get("type") in ("CVSS_V3", "CVSS_V3_1"):
            score = _cvss3_base_score(sev_entry.get("score", ""))
            if score is not None:
                cvss_score = score
                # Derive severity band from numeric score if no db_specific rating
                if not db_sev:
                    severity = _severity_from_cvss_score(score)

    return severity, cvss_score


def _severity_from_cvss_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def _cvss3_base_score(vector: str) -> float | None:
    """Compute CVSS v3.x base score from a metric vector string."""
    try:
        if not vector.startswith("CVSS:3"):
            return None
        parts = dict(p.split(":") for p in vector.split("/")[1:])

        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        scope_changed = parts["S"] == "C"
        pr_table = {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)}
        pr = pr_table[parts["PR"]][1 if scope_changed else 0]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        cia = {"N": 0.0, "L": 0.22, "H": 0.56}
        c_v, i_v, a_v = cia[parts["C"]], cia[parts["I"]], cia[parts["A"]]

        iss = 1.0 - (1.0 - c_v) * (1.0 - i_v) * (1.0 - a_v)
        impact = (
            7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
            if scope_changed
            else 6.42 * iss
        )

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            return 0.0

        raw = min(impact + exploitability, 10.0) if not scope_changed else min(1.08 * (impact + exploitability), 10.0)
        return math.ceil(raw * 10) / 10  # roundup to 1 decimal place
    except Exception:
        return None


def _extract_remediation(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return f"Upgrade to >= {event['fixed']}"
    return None
