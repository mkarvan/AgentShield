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

    def scan_file(
        self,
        path: Path | str,
        *,
        check_licenses: bool = False,
        deep: bool = False,
        transitive: bool = False,
        transitive_depth: int = 3,
    ) -> FileScanResult:
        """Synchronous manifest scan — wraps ascan_file(). Prefer ascan_file() in async contexts."""
        return asyncio.run(
            self.ascan_file(
                path,
                check_licenses=check_licenses,
                deep=deep,
                transitive=transitive,
                transitive_depth=transitive_depth,
            )
        )

    async def ascan_file(
        self,
        path: Path | str,
        *,
        check_licenses: bool = False,
        deep: bool = False,
        transitive: bool = False,
        transitive_depth: int = 3,
    ) -> FileScanResult:
        """Scan all packages declared in a manifest file.

        Auto-detects format from the filename (requirements.txt, package.json,
        Cargo.toml, package-lock.json). Returns an aggregate FileScanResult.

        Optional keyword arguments are applied to every ScanRequest created from
        the manifest, mirroring the single-package ``agentshield scan`` flags.
        """
        from agentshield.core.manifest import parse_manifest

        file_path = Path(path)
        requests = parse_manifest(file_path)

        if check_licenses or deep or transitive:
            requests = [
                req.model_copy(
                    update={
                        "check_licenses": check_licenses or req.check_licenses,
                        "deep": deep or req.deep,
                        "transitive": transitive or req.transitive,
                        "transitive_depth": transitive_depth,
                    }
                )
                for req in requests
            ]

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

        # Rate limit check — before running any online checks
        from agentshield.core.rate_limiter import RateLimiter

        rl = RateLimiter(self.config.cache.db_path, self.config.rate_limits)
        rate_findings = await rl.check(request.package)
        if rate_findings:
            return ScanResult(
                request=request,
                findings=rate_findings,
                max_severity=Severity.HIGH,
                decision=Decision(
                    action=DecisionAction.BLOCK,
                    reason=rate_findings[0].title,
                    findings=rate_findings,
                ),
                scan_duration_ms=int((time.monotonic() - start) * 1000),
                cache_hit=False,
            )

        # Run checks and trust score concurrently (trust score skipped in offline mode)
        from agentshield.analyzers.trust_score import TrustScoreResult, compute_trust_score

        if self.config.offline:
            findings = await self._run_offline_checks(request)
            trust_result: TrustScoreResult | None = None
        else:
            checks_coro = self._run_checks(request)
            trust_coro = compute_trust_score(request, db_path=self.config.cache.db_path)
            findings_raw, trust_raw = await asyncio.gather(
                checks_coro, trust_coro, return_exceptions=True
            )
            findings = findings_raw if isinstance(findings_raw, list) else []
            trust_result = trust_raw if isinstance(trust_raw, TrustScoreResult) else None

        # T4.1 heuristic: detect prompt-injected install requests (local, no I/O)
        from agentshield.analyzers.prompt_injection import check_prompt_injection

        t4_findings = await check_prompt_injection(request)
        if t4_findings:
            findings = _dedupe_findings(findings + t4_findings)

        # Static analysis (--deep only) — runs after enrichment checks regardless of offline mode
        if request.deep:
            deep_findings = await self._run_deep_checks(request)
            findings = _dedupe_findings(findings + deep_findings)

        # Drift detection — compare current decision against last recorded, emit D1.1 if regressed
        from agentshield.analyzers.drift_detector import DriftDetector

        dd = DriftDetector(self.config.cache.db_path)
        base_decision = self.response_engine.decide(findings, request)
        drift_findings = await dd.check(
            request.package, request.ecosystem.value, base_decision.action
        )
        if drift_findings:
            findings = _dedupe_findings(findings + drift_findings)

        # Fold trust-score finding into the findings list if below threshold
        if trust_result is not None:
            ts_finding = trust_result.to_finding(
                request,
                threshold=self.config.trust_score.threshold,
                min_signals=self.config.trust_score.min_signals,
            )
            if ts_finding is not None:
                findings = _dedupe_findings(findings + [ts_finding])

        max_sev = _max_severity(findings)
        decision = self.response_engine.decide(findings, request)

        result = ScanResult(
            request=request,
            findings=findings,
            max_severity=max_sev,
            decision=decision,
            scan_duration_ms=int((time.monotonic() - start) * 1000),
            cache_hit=False,
            trust_score=trust_result.score if trust_result is not None else None,
            trust_label=trust_result.label if trust_result is not None else None,
        )
        await self.cache.set(request, result)

        # Record current base decision for future drift detection
        await dd.record(request.package, request.ecosystem.value, base_decision.action)

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
        from agentshield.databases.nvd import NVD429Error, NVDClient
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

        # OSV is always index 0; use its result to decide NVD 429 log level
        osv_result = results[0]
        osv_has_findings = isinstance(osv_result, list) and bool(osv_result)

        findings: list[Finding] = []
        for source, r in zip(source_names, results, strict=False):
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                if source == "nvd" and isinstance(r, NVD429Error) and osv_has_findings:
                    logger.debug(
                        "NVD 429 for %s — OSV already returned results, skipping NVD",
                        request.package,
                    )
                else:
                    logger.warning("Check '%s' failed for %s: %s", source, request.package, r)

        # Deduplicate findings by rule_id (keep highest severity)
        return _dedupe_findings(findings)

    async def _run_deep_checks(self, request: ScanRequest) -> list[Finding]:
        """Download the package artifact and run the static-analysis suite.

        Deep static analysis is implemented for **PyPI only**: the wheel/sdist is
        downloaded and extracted, then semgrep, bandit, and the AST inspector run
        against the source. npm and cargo are not supported for deep scanning —
        ``extracted_package`` only fetches PyPI artifacts, and ``npm audit`` /
        ``cargo audit`` require a lockfile (``package-lock.json`` / ``Cargo.lock``)
        that published registry artifacts do not ship. For those ecosystems we
        emit an explicit informational finding instead of attempting an extraction
        that always fails; CVE/advisory coverage still comes from the online
        checks (OSV / NVD / GitHub Advisory) run in ``_run_checks``.
        """
        from agentshield.analyzers.bandit_runner import run_bandit
        from agentshield.analyzers.semgrep_runner import run_semgrep
        from agentshield.analyzers.setup_py_inspector import inspect_package_directory
        from agentshield.analyzers.wheel_extractor import WheelExtractionError, extracted_package
        from agentshield.core.models import Ecosystem
        from agentshield.core.rate_limiter import RateLimiter

        if request.ecosystem != Ecosystem.PYPI:
            logger.info(
                "Deep static analysis is not supported for ecosystem '%s' "
                "(package '%s') — skipping; CVE/advisory checks still apply",
                request.ecosystem.value,
                request.package,
            )
            return [
                Finding(
                    rule_id="DEEP.UNSUPPORTED",
                    title=f"Deep scan not supported for {request.ecosystem.value}",
                    description=(
                        f"Deep static analysis (--deep) is only implemented for PyPI; "
                        f"ecosystem '{request.ecosystem.value}' was skipped. CVE and "
                        f"advisory checks (OSV/NVD/GitHub) still ran for this package."
                    ),
                    severity=Severity.INFO,
                    source="deep_scan",
                    metadata={"ecosystem": request.ecosystem.value},
                )
            ]

        findings: list[Finding] = []

        # Cap each download at the per-session wheel budget and feed the actual
        # byte count back so max_wheel_mb_per_session is enforced across scans.
        rl = RateLimiter(self.config.cache.db_path, self.config.rate_limits)
        max_bytes = self.config.rate_limits.max_wheel_mb_per_session * 1024 * 1024

        try:
            async with extracted_package(
                request, max_bytes=max_bytes, on_download=rl.record_wheel_bytes
            ) as pkg_dir:
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
