from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

from agentshield.core.cache import ScanCache
from agentshield.core.config import Config
from agentshield.core.models import (
    Decision,
    DecisionAction,
    FileScanResult,
    Finding,
    ScanRequest,
    ScanResult,
    Severity,
)
from agentshield.core.response_engine import ResponseEngine

logger = logging.getLogger(__name__)

_SEVERITY_RANK: dict[str, int] = {
    "NONE": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


class AgentShield:
    def __init__(self, config: Config | None = None, config_path: Path | None = None) -> None:
        self.config = config or Config.load(config_path)
        self.cache = ScanCache(self.config.cache)
        self.response_engine = ResponseEngine(self.config)

    def scan(self, request: ScanRequest) -> ScanResult:
        """Synchronous scan — wraps ascan(). Prefer ascan() in async contexts."""
        return asyncio.run(self.ascan(request))

    def scan_file(self, path: Path | str) -> FileScanResult:
        """Synchronous manifest scan — wraps ascan_file(). Prefer ascan_file() in async contexts."""
        return asyncio.run(self.ascan_file(path))

    async def ascan_file(self, path: Path | str) -> FileScanResult:
        """Scan all packages declared in a manifest file.

        Auto-detects format from the filename (requirements.txt, package.json,
        Cargo.toml, package-lock.json). Returns an aggregate FileScanResult.
        """
        from agentshield.core.manifest import parse_manifest

        file_path = Path(path)
        requests = parse_manifest(file_path)

        _FILE_SCAN_CONCURRENCY = 10
        sem = asyncio.Semaphore(_FILE_SCAN_CONCURRENCY)

        async def _scan_one(req: ScanRequest) -> ScanResult:
            async with sem:
                return await self.ascan(req)

        raw = await asyncio.gather(*[_scan_one(req) for req in requests], return_exceptions=True)

        scan_results: list[ScanResult] = []
        for i, r in enumerate(raw):
            if isinstance(r, ScanResult):
                scan_results.append(r)
            elif isinstance(r, Exception):
                logger.warning("Scan failed for '%s': %s", requests[i].package, r)

        return FileScanResult.from_results(file_path, scan_results)

    async def ascan(self, request: ScanRequest) -> ScanResult:
        """Asynchronous scan — the main entry point for all integrations."""
        start = time.monotonic()

        # Denylist check — short-circuit before any I/O
        if request.package.lower() in {p.lower() for p in self.config.denylist}:
            return ScanResult(
                request=request,
                findings=[],
                max_severity=Severity.CRITICAL,
                decision=Decision(
                    action=DecisionAction.BLOCK,
                    reason=f"Package '{request.package}' is on the denylist",
                ),
                scan_duration_ms=0,
                cache_hit=False,
            )

        # Allowlist check — skip scan entirely
        if request.package.lower() in {p.lower() for p in self.config.allowlist}:
            return ScanResult(
                request=request,
                findings=[],
                max_severity=Severity.NONE,
                decision=Decision(
                    action=DecisionAction.ALLOW,
                    reason="Package is on the allowlist",
                ),
                scan_duration_ms=0,
                cache_hit=True,
            )

        # Cache lookup
        cached = await self.cache.get(request)
        if cached is not None:
            if request.transitive:
                cached = await self._add_transitive_results(request, cached)
            return cached

        # Run checks (online or offline depending on config)
        if self.config.offline:
            findings = await self._run_offline_checks(request)
        else:
            findings = await self._run_checks(request)

        # T4.1 heuristic: detect prompt-injected install requests (local, no I/O)
        from agentshield.analyzers.prompt_injection import check_prompt_injection

        t4_findings = await check_prompt_injection(request)
        if t4_findings:
            findings = _dedupe_findings(findings + t4_findings)

        # Static analysis (--deep only) — runs after enrichment checks regardless of offline mode
        if request.deep:
            deep_findings = await self._run_deep_checks(request)
            findings = _dedupe_findings(findings + deep_findings)

        max_sev = _max_severity(findings)
        decision = self.response_engine.decide(findings, request)

        result = ScanResult(
            request=request,
            findings=findings,
            max_severity=max_sev,
            decision=decision,
            scan_duration_ms=int((time.monotonic() - start) * 1000),
            cache_hit=False,
        )
        await self.cache.set(request, result)

        # Persist LOG_ASYNC decisions for posture report aggregation
        if decision.action == DecisionAction.LOG_ASYNC and findings:
            import json as _json

            await self.cache.append_async_log(
                package=request.package,
                version=request.version,
                ecosystem=request.ecosystem.value,
                findings_json=_json.dumps([f.model_dump() for f in findings]),
                reason=decision.reason,
            )

        if request.transitive:
            result = await self._add_transitive_results(request, result)

        return result

    async def _add_transitive_results(
        self, request: ScanRequest, primary: ScanResult
    ) -> ScanResult:
        """Resolve and scan all transitive deps of *request*, attach to *primary*."""
        from agentshield.core.deps import DepSpec, resolve_deps

        deps = await resolve_deps(
            request.package,
            request.version,
            request.ecosystem,
            max_depth=request.transitive_depth,
        )
        if not deps:
            return primary

        _TRANSITIVE_CONCURRENCY = 10
        sem = asyncio.Semaphore(_TRANSITIVE_CONCURRENCY)

        async def _scan_dep(dep: DepSpec) -> ScanResult:
            async with sem:
                dep_req = ScanRequest(
                    package=dep.package,
                    version=None,
                    ecosystem=dep.ecosystem,
                    source=request.source,
                    transitive=False,  # never recurse into transitive deps
                )
                return await self.ascan(dep_req)

        raw = await asyncio.gather(*[_scan_dep(d) for d in deps], return_exceptions=True)

        transitive_results: list[ScanResult] = []
        for i, r in enumerate(raw):
            if isinstance(r, ScanResult):
                transitive_results.append(r)
            elif isinstance(r, Exception):
                logger.warning("Transitive scan failed for '%s': %s", deps[i].package, r)

        return primary.model_copy(update={"transitive_results": transitive_results})

    async def _run_checks(self, request: ScanRequest) -> list[Finding]:
        """Full online enrichment: OSV + NVD + GitHub Advisory + typosquatting + malicious DB."""
        from agentshield.analyzers.typosquatting import TyposquattingChecker
        from agentshield.databases.github_advisory import GitHubAdvisoryClient
        from agentshield.databases.malicious_db import MaliciousDB
        from agentshield.databases.nvd import NVDClient
        from agentshield.databases.osv import OSVClient

        tasks: list[Any] = [
            OSVClient().scan(request),
            NVDClient(api_key=self.config.api.nvd_api_key).scan(request),
            GitHubAdvisoryClient(token=self.config.api.github_token).scan(request),
            TyposquattingChecker().scan(request),
            MaliciousDB().check(request, db_path=self.config.cache.db_path),
        ]
        source_names = ["osv", "nvd", "github_advisory", "typosquatting", "malicious_db"]

        if request.check_licenses or self.config.license_policy.mode != "disabled":
            from agentshield.analyzers.license_checker import LicenseChecker
            from agentshield.core.config import LicensePolicy as _LP

            _policy = self.config.license_policy
            if request.check_licenses and _policy.mode == "disabled":
                _policy = _LP(mode="denylist")
            tasks.append(LicenseChecker(_policy).check(request))
            source_names.append("license_checker")

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for source, r in zip(source_names, results, strict=False):
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.warning("Check '%s' failed for %s: %s", source, request.package, r)

        # Deduplicate findings by rule_id (keep highest severity)
        return _dedupe_findings(findings)

    async def _run_deep_checks(self, request: ScanRequest) -> list[Finding]:
        """Download wheel and run static analysis suite (semgrep, bandit, AST inspector)."""
        from agentshield.analyzers.bandit_runner import run_bandit
        from agentshield.analyzers.cargo_audit_runner import run_cargo_audit
        from agentshield.analyzers.npm_audit_runner import run_npm_audit
        from agentshield.analyzers.semgrep_runner import run_semgrep
        from agentshield.analyzers.setup_py_inspector import inspect_package_directory
        from agentshield.analyzers.wheel_extractor import WheelExtractionError, extracted_package
        from agentshield.core.models import Ecosystem

        findings: list[Finding] = []

        if request.ecosystem == Ecosystem.PYPI:
            try:
                async with extracted_package(request) as pkg_dir:
                    results = await asyncio.gather(
                        run_semgrep(pkg_dir, request),
                        run_bandit(pkg_dir, request),
                        return_exceptions=True,
                    )
                    for name, r in zip(("semgrep", "bandit"), results, strict=False):
                        if isinstance(r, list):
                            findings.extend(r)
                        elif isinstance(r, Exception):
                            logger.warning("Deep check '%s' failed: %s", name, r)

                    # AST inspector is synchronous; run directly
                    try:
                        ast_findings = inspect_package_directory(pkg_dir, request)
                        findings.extend(ast_findings)
                    except Exception as exc:
                        logger.warning("setup_py_inspector failed: %s", exc)

            except WheelExtractionError as exc:
                logger.warning("Could not download/extract package for deep scan: %s", exc)
            except Exception as exc:
                logger.warning("Deep scan failed with unexpected error: %s", exc)

        elif request.ecosystem == Ecosystem.NPM:
            try:
                async with extracted_package(request) as pkg_dir:
                    npm_findings = await run_npm_audit(pkg_dir, request)
                    findings.extend(npm_findings)
            except Exception as exc:
                logger.warning("npm deep scan failed: %s", exc)

        elif request.ecosystem == Ecosystem.CARGO:
            try:
                async with extracted_package(request) as pkg_dir:
                    cargo_findings = await run_cargo_audit(pkg_dir, request)
                    findings.extend(cargo_findings)
            except Exception as exc:
                logger.warning("cargo deep scan failed: %s", exc)

        return findings

    async def _run_offline_checks(self, request: ScanRequest) -> list[Finding]:
        """Offline enrichment: local SQLite only — no network calls."""
        from agentshield.analyzers.typosquatting import TyposquattingChecker
        from agentshield.databases.malicious_db import MaliciousDB

        tasks: list[Any] = [
            TyposquattingChecker().scan(request),
            MaliciousDB().check(request, db_path=self.config.cache.db_path),
            _query_cve_mirror(request, self.config.cache.db_path),
        ]
        source_names = ["typosquatting", "malicious_db", "cve_mirror"]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[Finding] = []
        for source, r in zip(source_names, results, strict=False):
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.warning("Offline check '%s' failed for %s: %s", source, request.package, r)

        return _dedupe_findings(findings)


async def _query_cve_mirror(request: ScanRequest, db_path: Path) -> list[Finding]:
    """Query the local cve_mirror table for offline CVE lookups."""
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import CacheConfig
    from agentshield.core.models import Severity

    _SEV_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }

    cache = ScanCache(CacheConfig(db_path=db_path))
    rows = await cache.query_cve_mirror(request.package, request.ecosystem.value)

    findings: list[Finding] = []
    for row in rows:
        sev = _SEV_MAP.get(row.get("severity", ""), Severity.MEDIUM)
        findings.append(
            Finding(
                rule_id=row["id"],
                title=row.get("description", row["id"])[:200],
                description=row.get("description") or "",
                severity=sev,
                source="cve_mirror",
                references=[],
                cvss_score=row.get("cvss_score"),
                remediation=None,
                metadata={"offline": True},
            )
        )
    return findings


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings by rule_id, keeping the one with the highest severity."""
    seen: dict[str, Finding] = {}
    for f in findings:
        existing = seen.get(f.rule_id)
        if existing is None or f.severity > existing.severity:
            seen[f.rule_id] = f
    return list(seen.values())


def _max_severity(findings: list[Finding]) -> Severity:
    if not findings:
        return Severity.NONE
    return max(findings, key=lambda f: _SEVERITY_RANK[f.severity.value]).severity
