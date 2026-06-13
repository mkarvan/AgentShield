"""GitHub Advisory Database client (GraphQL).

Requires a GitHub Personal Access Token with no special scopes — the
Advisory Database is public, so a classic token with no scopes works fine.

Supply the token via:
  • config.toml [api] section: github_token = "ghp_..."
  • Environment variable: GITHUB_TOKEN=ghp_...

Without a token, this client is silently skipped (scan returns []).

Reference: https://docs.github.com/en/graphql/reference/objects#securityvulnerability
"""

from __future__ import annotations

import logging

import httpx

from agentshield.core.models import Ecosystem, Finding, ScanRequest, Severity

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

# GitHub Advisory ecosystem identifiers
_ECOSYSTEM_MAP: dict[Ecosystem, str] = {
    Ecosystem.PYPI: "PIP",
    Ecosystem.NPM: "NPM",
    Ecosystem.CARGO: "RUST",
}

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
  securityVulnerabilities(
    ecosystem: $ecosystem
    package: $package
    first: 20
    orderBy: {field: UPDATED_AT, direction: DESC}
  ) {
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        identifiers { type value }
        references { url }
        cvss { score vectorString }
        publishedAt
        withdrawnAt
      }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""


class GitHubAdvisoryClient:
    """Fetches security advisories from the GitHub Advisory Database via GraphQL."""

    def __init__(self, token: str | None = None) -> None:
        self._token = token

    async def scan(self, request: ScanRequest) -> list[Finding]:
        if not self._token:
            return []

        gh_ecosystem = _ECOSYSTEM_MAP.get(request.ecosystem)
        if gh_ecosystem is None:
            return []

        try:
            return await self._fetch_findings(request, gh_ecosystem)
        except Exception as exc:
            logger.warning("GitHub Advisory scan failed for %s: %s", request.package, exc)
            return []

    async def _fetch_findings(self, request: ScanRequest, gh_ecosystem: str) -> list[Finding]:
        headers = {
            "Authorization": f"bearer {self._token}",
            "Content-Type": "application/json",
        }
        payload = {
            "query": _QUERY,
            "variables": {
                "ecosystem": gh_ecosystem,
                "package": request.package,
            },
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(GITHUB_GRAPHQL_URL, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        if "errors" in data:
            raise ValueError(f"GraphQL errors: {data['errors']}")

        nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])

        findings: list[Finding] = []
        for node in nodes:
            finding = _node_to_finding(node, request)
            if finding is not None:
                findings.append(finding)

        return findings


def _node_to_finding(node: dict, request: ScanRequest) -> Finding | None:
    advisory = node.get("advisory", {})

    # Skip withdrawn advisories
    if advisory.get("withdrawnAt"):
        return None

    ghsa_id: str = advisory.get("ghsaId", "")
    if not ghsa_id:
        return None

    # Prefer CVE identifier if present, fall back to GHSA
    identifiers = advisory.get("identifiers", [])
    rule_id = next(
        (i["value"] for i in identifiers if i.get("type") == "CVE"),
        ghsa_id,
    )

    severity_str = advisory.get("severity", "")
    severity = _SEVERITY_MAP.get(severity_str.upper(), Severity.MEDIUM)

    cvss = advisory.get("cvss") or {}
    cvss_score: float | None = cvss.get("score")

    references = [r["url"] for r in advisory.get("references", []) if r.get("url")]

    patched = node.get("firstPatchedVersion", {})
    remediation: str | None = None
    if patched and patched.get("identifier"):
        remediation = f"Upgrade to >= {patched['identifier']}"

    vuln_range = node.get("vulnerableVersionRange", "")

    description = advisory.get("description", "")
    summary = advisory.get("summary", "") or description[:200]

    return Finding(
        rule_id=rule_id,
        title=summary,
        description=description,
        severity=severity,
        source="github_advisory",
        references=references,
        cvss_score=float(cvss_score) if cvss_score is not None else None,
        remediation=remediation,
        metadata={"ghsa_id": ghsa_id, "vulnerable_range": vuln_range},
    )
