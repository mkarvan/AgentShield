from __future__ import annotations

import asyncio
import time
from importlib.metadata import version as _meta_version
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from agentshield.core.models import (
    Decision,
    DecisionAction,
    Ecosystem,
    FileScanResult,
    Finding,
    ScanRequest,
    ScanResult,
)
from agentshield.core.scanner import AgentShield

app = typer.Typer(name="agentshield", help="Security layer for AI agent package installations")
console = Console()


def _version_callback(value: bool | None) -> None:
    if value:
        try:
            ver = _meta_version("agentshield")
        except Exception:
            ver = "0.0.0-dev"
        typer.echo(f"agentshield {ver}")
        raise typer.Exit()


@app.callback()
def callback(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Security layer for AI agent package installations."""
    import sys

    import agentshield as _pkg

    try:
        installed = _meta_version("agentshield")
        if installed != _pkg.__version__:
            print(
                f"[agentshield] Warning: running v{_pkg.__version__} but "
                f"v{installed} is installed. Your PATH may be pointing to a stale binary. "
                "Run 'which agentshield' and ensure your venv is active.",
                file=sys.stderr,
            )
    except Exception:
        pass


@app.command()
def scan(
    package: str = typer.Argument(
        ..., help="Package name (optionally with ==version, e.g. requests==2.28.0)"
    ),
    ecosystem: Ecosystem = typer.Option(Ecosystem.PYPI, "--ecosystem", "-e", help="pypi|npm|cargo"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    deep: bool = typer.Option(
        False, "--deep", help="Run static analysis in addition to CVE lookups"
    ),
    offline: bool = typer.Option(False, "--offline", help="Use only local DB — no network calls"),
    transitive: bool = typer.Option(
        False, "--transitive", "-T", help="Resolve and scan transitive dependencies"
    ),
    transitive_depth: int = typer.Option(
        3, "--transitive-depth", help="Maximum depth for transitive dependency resolution (1-10)"
    ),
    check_licenses: bool = typer.Option(
        False,
        "--check-licenses",
        help="Check package license against the configured license policy (default: denylist)",
    ),
) -> None:
    """Scan a package for security vulnerabilities."""
    name, _, version = package.partition("==")
    request = ScanRequest(
        package=name.strip(),
        version=version.strip() or None,
        ecosystem=ecosystem,
        source="cli",
        deep=deep,
        transitive=transitive,
        transitive_depth=transitive_depth,
        check_licenses=check_licenses,
    )

    from agentshield.core.config import Config

    cfg = Config.load(config)
    if offline:
        cfg = cfg.model_copy(update={"offline": True})

    shield = AgentShield(config=cfg)
    t0 = time.monotonic()
    result = asyncio.run(_scan_with_progress(shield, request, deep=deep))
    wall_ms = int((time.monotonic() - t0) * 1000)

    _print_result(result, wall_ms)

    if result.decision.action == DecisionAction.BLOCK:
        raise typer.Exit(code=1)


async def _scan_with_progress(
    shield: AgentShield, request: ScanRequest, *, deep: bool
) -> ScanResult:
    """Run the scan and show a Rich spinner if it exceeds 2 seconds."""
    _SPINNER_DELAY = 2.0
    _description = (
        f"[cyan]Scanning {request.package} (deep mode — downloading + analyzing)…[/cyan]"
        if deep
        else f"[cyan]Scanning {request.package}…[/cyan]"
    )

    scan_task = asyncio.ensure_future(shield.ascan(request))

    try:
        # Wait up to 2 s before showing the spinner
        result = await asyncio.wait_for(asyncio.shield(scan_task), timeout=_SPINNER_DELAY)
        return result
    except TimeoutError:
        pass

    # Scan is taking > 2 s — show a spinner until it finishes
    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task(_description, total=None)
        result = await scan_task

    return result


@app.command()
def posture(
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to this file"),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|html|markdown"),
    tools: str | None = typer.Option(
        None,
        "--tools",
        "-t",
        help="Comma-separated list of agent tool names to classify (e.g. bash,read_file,web_search)",
    ),
    async_log_hours: int = typer.Option(
        24, "--log-hours", help="Hours of async report log to include"
    ),
    skip_packages: bool = typer.Option(
        False, "--skip-packages", help="Skip installed-package CVE scan (faster)"
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
) -> None:
    """Generate a security posture report for the current agent environment.

    \b
    agentshield posture                          # terminal output
    agentshield posture --format json            # JSON to stdout
    agentshield posture --format html -o r.html  # HTML file
    agentshield posture --format markdown        # Markdown to stdout
    agentshield posture --tools bash,read_file   # classify tool permissions
    """
    from agentshield.core.config import Config
    from agentshield.reports.posture import run_posture_check
    from agentshield.reports.renderers import (
        render_html,
        render_json,
        render_markdown,
        render_terminal,
    )

    cfg = Config.load(config)
    tool_names = [t.strip() for t in tools.split(",")] if tools else None

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Running posture check…[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("posture", total=None)
        report = asyncio.run(
            run_posture_check(
                db_path=cfg.cache.db_path,
                tool_names=tool_names,
                async_log_hours=async_log_hours,
                skip_package_scan=skip_packages,
                offline=cfg.offline,
            )
        )

    if fmt == "terminal":
        render_terminal(report)
    elif fmt == "json":
        text = render_json(report)
        if output:
            output.write_text(text)
            console.print(f"[green]JSON report written to {output}[/green]")
        else:
            print(text)
    elif fmt == "html":
        text = render_html(report)
        if output:
            output.write_text(text)
            console.print(f"[green]HTML report written to {output}[/green]")
        else:
            print(text)
    elif fmt == "markdown":
        text = render_markdown(report)
        if output:
            output.write_text(text)
            console.print(f"[green]Markdown report written to {output}[/green]")
        else:
            print(text)
    else:
        console.print(f"[red]Unknown format: {fmt!r}[/red]")
        console.print("Available formats: terminal | json | html | markdown")
        raise typer.Exit(code=1)

    if fmt == "terminal" and output:
        console.print("[yellow]--output is ignored for terminal format.[/yellow]")


@app.command()
def cache(
    action: str = typer.Argument("stats", help="clear|stats|warm"),
    ecosystems: str = typer.Option(
        "all",
        "--ecosystems",
        help="Comma-separated list of ecosystems to warm: pypi,npm,cargo (default: all)",
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
) -> None:
    """Manage the local scan cache.

    \b
    agentshield cache stats       Show cache statistics
    agentshield cache clear       Delete all cached scan results
    agentshield cache warm        Download OSV bulk exports and populate local DB
    """
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import Config

    cfg = Config.load(config)
    sc = ScanCache(cfg.cache)

    if action == "clear":
        deleted = asyncio.run(sc.clear())
        console.print(f"[green]Cleared {deleted} cached entries.[/green]")

    elif action == "stats":
        from agentshield.databases.malicious_db import MaliciousDB

        stats = asyncio.run(sc.stats())
        mdb = MaliciousDB()
        curated = mdb._get_curated()
        curated_count = sum(len(v) for v in curated.values() if isinstance(v, list))
        cached_mal = stats.get("malicious_packages", 0)
        console.print(f"[bold]Cache stats[/bold] — {cfg.cache.db_path}")
        console.print(f"  Scan results : {stats['live']} live / {stats['expired']} expired")
        console.print(f"  CVE mirror   : {stats.get('cve_mirror', 0)} entries")
        console.print(f"  Malicious DB : {curated_count} curated + {cached_mal} cached from OSV")

    elif action == "warm":
        asyncio.run(_cmd_warm(cfg, ecosystems))

    else:
        console.print(f"[red]Unknown action: {action!r}[/red]")
        console.print("Available actions: clear | stats | warm")
        raise typer.Exit(code=1)


async def _cmd_warm(cfg: object, ecosystems_str: str) -> None:
    from agentshield.databases.warm import warm_cache

    real_cfg = cfg

    if ecosystems_str.lower() == "all":
        target = list(Ecosystem)
    else:
        target = []
        for name in ecosystems_str.split(","):
            name = name.strip().lower()
            try:
                target.append(Ecosystem(name))
            except ValueError:
                console.print(f"[yellow]Unknown ecosystem '{name}' — skipping.[/yellow]")

    if not target:
        console.print("[red]No valid ecosystems to warm.[/red]")
        return

    console.print(
        f"[bold]Warming cache[/bold] for: {', '.join(e.value for e in target)}\n"
        f"  DB path: {real_cfg.cache.db_path}\n"  # type: ignore[attr-defined]
        "  This downloads OSV bulk exports and may take up to 5 minutes."
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        overall = progress.add_task("[cyan]Warming...", total=len(target))

        def on_progress(ecosystem: str, phase: str, count: int) -> None:
            if phase == "downloading":
                progress.update(overall, description=f"[cyan]Downloading {ecosystem}...")
            elif phase == "parsing":
                progress.update(overall, description=f"[cyan]Parsing {ecosystem}...")
            elif phase == "done":
                progress.update(
                    overall, advance=1, description=f"[green]{ecosystem} done ({count} advisories)"
                )

        t0 = time.monotonic()
        stats = await warm_cache(
            db_path=real_cfg.cache.db_path,  # type: ignore[attr-defined]
            ecosystems=target,
            progress_callback=on_progress,
        )
        elapsed = time.monotonic() - t0

    console.print(f"\n[bold green]Cache warm-up complete[/bold green] in {elapsed:.1f}s")
    console.print(f"  Ecosystems : {', '.join(stats.ecosystems_processed)}")
    console.print(f"  Advisories : {stats.advisories_scanned} scanned")
    console.print(f"  CVE mirror : {stats.cve_rows_inserted} entries inserted")
    console.print(f"  Malicious  : {stats.malicious_rows_inserted} packages recorded")

    if stats.errors:
        console.print(f"\n[yellow]Warnings ({len(stats.errors)}):[/yellow]")
        for err in stats.errors:
            console.print(f"  • {err}")


@app.command("scan-file")
def scan_file(
    path: Path = typer.Argument(
        ...,
        help="Path to manifest file (requirements.txt, package.json, Cargo.toml, package-lock.json)",
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    offline: bool = typer.Option(False, "--offline", help="Use only local DB — no network calls"),
    deep: bool = typer.Option(
        False, "--deep", help="Run static analysis in addition to CVE lookups"
    ),
    transitive: bool = typer.Option(
        False, "--transitive", "-T", help="Resolve and scan transitive dependencies"
    ),
    transitive_depth: int = typer.Option(
        3, "--transitive-depth", help="Maximum depth for transitive dependency resolution (1-10)"
    ),
    check_licenses: bool = typer.Option(
        False,
        "--check-licenses",
        help="Check package licenses against the configured license policy (default: denylist)",
    ),
) -> None:
    """Scan all packages declared in a manifest file.

    \b
    agentshield scan-file requirements.txt
    agentshield scan-file package.json
    agentshield scan-file Cargo.toml
    agentshield scan-file package-lock.json
    """
    from agentshield.core.config import Config

    cfg = Config.load(config)
    if offline:
        cfg = cfg.model_copy(update={"offline": True})

    shield = AgentShield(config=cfg)

    with Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]Scanning {path.name}…[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("scan-file", total=None)
        result = asyncio.run(
            shield.ascan_file(
                path,
                check_licenses=check_licenses,
                deep=deep,
                transitive=transitive,
                transitive_depth=transitive_depth,
            )
        )

    _print_file_result(result)

    if result.aggregate_decision.action == DecisionAction.BLOCK:
        raise typer.Exit(code=1)


@app.command()
def sbom(
    path: Path = typer.Argument(
        ...,
        help="Path to manifest file (requirements.txt, package.json, Cargo.toml, package-lock.json)",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write SBOM to this file"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    offline: bool = typer.Option(False, "--offline", help="Use only local DB — no network calls"),
) -> None:
    """Scan a manifest file and output a CycloneDX v1.4 SBOM.

    \b
    agentshield sbom requirements.txt             # JSON to stdout
    agentshield sbom package.json -o sbom.json    # JSON to file
    """
    from agentshield.core.config import Config
    from agentshield.core.sbom import generate_sbom_json

    cfg = Config.load(config)
    if offline:
        cfg = cfg.model_copy(update={"offline": True})

    shield = AgentShield(config=cfg)

    with Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]Scanning {path.name} for SBOM…[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("sbom", total=None)
        file_result = asyncio.run(shield.ascan_file(path))

    sbom_text = generate_sbom_json(file_result.results, source_path=str(path))

    if output:
        output.write_text(sbom_text)
        console.print(f"[green]SBOM written to {output}[/green]")
    else:
        print(sbom_text)

    if file_result.aggregate_decision.action == DecisionAction.BLOCK:
        raise typer.Exit(code=1)


@app.command("drift-check")
def drift_check(
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json"),
) -> None:
    """Re-scan all previously-allowed packages for new vulnerabilities.

    \b
    agentshield drift-check              # scan allowed packages, terminal output
    agentshield drift-check --format json  # JSON output
    """
    from agentshield.core.config import Config

    cfg = Config.load(config)
    shield = AgentShield(config=cfg)

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Checking for drift in previously-allowed packages…[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("drift-check", total=None)
        drift_results = asyncio.run(_cmd_drift_check(shield, cfg))

    if fmt == "json":
        import json as _json

        output = [
            {
                "package": pkg,
                "ecosystem": eco,
                "finding": f.model_dump(),
            }
            for pkg, eco, f in drift_results
        ]
        print(_json.dumps(output, indent=2))
        return

    if not drift_results:
        console.print(
            "[green]No drift detected — all previously-allowed packages are still clean.[/green]"
        )
        return

    console.print(
        f"\n[bold yellow]Drift detected in {len(drift_results)} package(s):[/bold yellow]\n"
    )
    for pkg, eco, f in drift_results:
        sev_color = {"HIGH": "orange3", "MEDIUM": "yellow"}.get(f.severity.value, "white")
        console.print(
            f"  [{sev_color}]{f.severity.value}[/{sev_color}]  "
            f"[bold]{pkg}[/bold] ({eco})  [{f.rule_id}]"
        )
        console.print(f"    {f.title}")
        if f.remediation:
            console.print(f"    [dim]Fix: {f.remediation}[/dim]")
        console.print()

    raise typer.Exit(code=1)


async def _cmd_drift_check(shield: AgentShield, cfg: object) -> list[tuple[str, str, Finding]]:
    """Re-scan all previously-allowed packages and return (pkg, eco, finding) triples."""
    from agentshield.core.cache import ScanCache
    from agentshield.core.config import Config

    real_cfg: Config = cfg  # type: ignore[assignment]
    cache = ScanCache(real_cfg.cache)
    allowed_pairs = await cache.get_previously_allowed()

    if not allowed_pairs:
        return []

    _CONCURRENCY = 5
    sem = asyncio.Semaphore(_CONCURRENCY)

    async def _rescan(pkg: str, eco_str: str) -> list[tuple[str, str, Finding]]:
        async with sem:
            try:
                eco = Ecosystem(eco_str)
            except ValueError:
                return []
            req = ScanRequest(package=pkg, ecosystem=eco, source="drift-check")
            result = await shield.ascan(req)
            # Collect D1.1 findings only
            drift_findings = [f for f in result.findings if f.rule_id == "D1.1"]
            return [(pkg, eco_str, f) for f in drift_findings]

    raw = await asyncio.gather(*[_rescan(p, e) for p, e in allowed_pairs], return_exceptions=True)
    out: list[tuple[str, str, Finding]] = []
    for r in raw:
        if isinstance(r, list):
            out.extend(r)
    return out


@app.command("diff-scan")
def diff_scan(
    old_manifest: Path = typer.Argument(..., help="Old manifest file"),
    new_manifest: Path = typer.Argument(..., help="New manifest file"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
) -> None:
    """Scan only packages that changed between two manifest snapshots.

    \b
    agentshield diff-scan old-requirements.txt new-requirements.txt
    agentshield diff-scan old-package.json new-package.json
    """
    from agentshield.analyzers.diff_scanner import run_diff_scan
    from agentshield.core.config import Config

    cfg = Config.load(config)
    shield = AgentShield(config=cfg)

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Computing diff and scanning changed packages…[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("diff-scan", total=None)
        result = asyncio.run(run_diff_scan(shield, old_manifest, new_manifest))

    _print_diff_result(result)

    if result.aggregate_decision.action == DecisionAction.BLOCK:
        raise typer.Exit(code=1)


@app.command("scan-docker")
def scan_docker(
    dockerfile: Path = typer.Argument(..., help="Path to Dockerfile"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    offline: bool = typer.Option(False, "--offline", help="Use only local DB — no network calls"),
) -> None:
    """Scan packages from RUN pip/npm/cargo install commands in a Dockerfile.

    \b
    agentshield scan-docker Dockerfile
    agentshield scan-docker path/to/Dockerfile
    """
    from agentshield.analyzers.dockerfile_scanner import parse_dockerfile
    from agentshield.core.config import Config

    cfg = Config.load(config)
    if offline:
        cfg = cfg.model_copy(update={"offline": True})

    shield = AgentShield(config=cfg)

    requests_list = parse_dockerfile(dockerfile)
    if not requests_list:
        console.print("[yellow]No package install commands found in Dockerfile.[/yellow]")
        return

    with Progress(
        SpinnerColumn(),
        TextColumn(f"[cyan]Scanning {len(requests_list)} package(s) from Dockerfile…[/cyan]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("scan-docker", total=None)

        async def _run() -> FileScanResult:
            import asyncio as _asyncio

            _CONCURRENCY = 10
            sem = _asyncio.Semaphore(_CONCURRENCY)

            async def _one(req: ScanRequest) -> ScanResult:
                async with sem:
                    return await shield.ascan(req)

            raw = await _asyncio.gather(*[_one(r) for r in requests_list], return_exceptions=True)
            results: list[ScanResult] = []
            for i, r in enumerate(raw):
                if isinstance(r, ScanResult):
                    results.append(r)
                elif isinstance(r, Exception):
                    console.print(
                        f"[yellow]Scan failed for {requests_list[i].package}: {r}[/yellow]"
                    )
            return FileScanResult.from_results(dockerfile, results)

        result = asyncio.run(_run())

    _print_file_result(result)

    if result.aggregate_decision.action == DecisionAction.BLOCK:
        raise typer.Exit(code=1)


@app.command()
def guard(
    shell: str | None = typer.Option(
        None, "--shell", help="Shell to wrap (default: $SHELL or bash)"
    ),
) -> None:
    """Start an interactive shell with package install interception.

    Wraps pip, npm, and cargo — any install command is scanned by AgentShield
    before it runs.  Exit the guarded shell normally to return to your session.

    \b
    agentshield guard
    agentshield guard --shell zsh
    """
    from agentshield.guard.shell_wrapper import ShellGuard

    guard_instance = ShellGuard()
    exit_code = guard_instance.start(shell=shell)
    raise typer.Exit(code=exit_code)


@app.command(
    "guard-scan-cmd",
    hidden=True,
    context_settings={"ignore_unknown_options": True},
)
def guard_scan_cmd(
    args: list[str] = typer.Argument(..., help="Command tokens to scan (e.g. pip install pkg)"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
) -> None:
    """Internal command used by agentshield guard shell wrappers.

    Scans all packages detected in a shell install command.
    Exits 0 if safe, 1 if any package is blocked.
    Also emits warnings for system package manager invocations.
    """
    import shlex
    from pathlib import Path

    from agentshield.analyzers.syspkg_detector import detect_syspkg_commands
    from agentshield.core.config import Config
    from agentshield.enforce import registry

    command = shlex.join(args)
    err_console = Console(stderr=True)
    cfg = Config.load(config)
    shield = AgentShield(config=cfg)

    # ── system package manager detection ───────────────────────────────────
    syspkg_warnings = detect_syspkg_commands(command)
    if syspkg_warnings:
        for w in syspkg_warnings:
            console.print(f"[yellow]AgentShield WARNING [SP1.1]: {w.title}[/yellow]")

        # ── CVE scanning for detected system packages (v0.9.0) ──────────
        if cfg.syspkg.enabled and cfg.syspkg.cve_scan and not cfg.offline:
            from agentshield.analyzers.syspkg_cve import SysPkgCVEScanner

            cve_scanner = SysPkgCVEScanner(db_path=cfg.cache.db_path)
            cve_findings = asyncio.run(cve_scanner.scan_warnings(syspkg_warnings))

            if cve_findings:
                # Evaluate each finding against syspkg severity policy
                syspkg_policy = cfg.syspkg.severity_policy
                from agentshield.core.models import ResponseMode

                _MODE_TO_ACTION = {
                    ResponseMode.BLOCK: DecisionAction.BLOCK,
                    ResponseMode.WARN_CONFIRM: DecisionAction.NEEDS_CONFIRMATION,
                    ResponseMode.IGNORE: DecisionAction.ALLOW,
                    ResponseMode.ASYNC_REPORT: DecisionAction.LOG_ASYNC,
                }
                action_order = [
                    DecisionAction.ALLOW,
                    DecisionAction.LOG_ASYNC,
                    DecisionAction.NEEDS_CONFIRMATION,
                    DecisionAction.BLOCK,
                ]

                worst_action = DecisionAction.ALLOW
                cve_blocked: list[tuple[str, str]] = []
                cve_warned: list[tuple[str, str]] = []

                for finding in cve_findings:
                    # Rule-level override first, then syspkg policy
                    if finding.rule_id in cfg.rules and "mode" in cfg.rules[finding.rule_id]:
                        mode = ResponseMode(cfg.rules[finding.rule_id]["mode"])
                    else:
                        mode = syspkg_policy.for_severity(finding.severity)
                    action = _MODE_TO_ACTION[mode]

                    if action == DecisionAction.BLOCK:
                        cve_blocked.append((finding.rule_id, finding.title))
                    elif action in (
                        DecisionAction.NEEDS_CONFIRMATION,
                        DecisionAction.LOG_ASYNC,
                    ):
                        cve_warned.append((finding.rule_id, finding.title))

                    if action_order.index(action) > action_order.index(worst_action):
                        worst_action = action

                if cve_warned:
                    console.print(
                        f"[yellow]AgentShield: {len(cve_warned)} CVE(s) flagged for review[/yellow]",
                    )
                    for rule_id, title in cve_warned:
                        console.print(f"  • {rule_id}: {title}")

                if cve_blocked:
                    console.print(
                        f"[red]AgentShield BLOCKED {len(cve_blocked)} CVE(s):[/red]",
                    )
                    for rule_id, title in cve_blocked:
                        console.print(f"  • {rule_id}: {title}")
                    raise typer.Exit(code=1)

    manifest_paths, manifest_suspicions = registry.parse_manifests(command)
    suspicions = registry.find_suspicions(command) + manifest_suspicions
    if suspicions:
        err_console.print("[red]AgentShield: cannot verify package source:[/red]")
        for s in suspicions:
            err_console.print(f"  • {s}")
        raise typer.Exit(code=1)

    installs = registry.parse_command(command)
    if not installs and not manifest_paths:
        return  # no packages detected, allow

    # Recognised but unverifiable managers (gem/go — no scan backend) cannot be
    # cleared, so fail closed.
    unverifiable: list[tuple[str, str]] = []
    requests_list: list[ScanRequest] = []
    for inst in installs:
        if inst.ecosystem is None:
            reason = (
                inst.unverifiable_reason or f"'{inst.manager}' has no scan backend — cannot verify"
            )
            for pkg in inst.packages or ["<unspecified>"]:
                unverifiable.append((pkg, reason))
            continue
        requests_list.extend(
            ScanRequest(package=pkg, ecosystem=inst.ecosystem, source="guard")
            for pkg in inst.packages
        )

    # (label, decision) pairs covering both named packages and manifest files.
    # Scanner errors fail closed (treated as BLOCK).
    async def _run() -> list[tuple[str, Decision]]:
        results: list[tuple[str, Decision]] = []
        for req in requests_list:
            try:
                res = await shield.ascan(req)
                results.append((req.package, res.decision))
            except Exception as exc:  # noqa: BLE001 — fail closed
                results.append(
                    (
                        req.package,
                        Decision(
                            action=DecisionAction.BLOCK,
                            reason=f"scan failed ({exc}); blocking to fail closed",
                        ),
                    )
                )
        for manifest in manifest_paths:
            manifest_path = Path(manifest)
            if not manifest_path.exists():
                continue
            try:
                file_res = await shield.ascan_file(manifest_path)
                results.append((manifest, file_res.aggregate_decision))
            except Exception as exc:  # noqa: BLE001 — fail closed
                results.append(
                    (
                        manifest,
                        Decision(
                            action=DecisionAction.BLOCK,
                            reason=f"scan failed ({exc}); blocking to fail closed",
                        ),
                    )
                )
        return results

    results = asyncio.run(_run())

    blocked = [(label, d.reason) for label, d in results if d.action == DecisionAction.BLOCK]
    blocked.extend(unverifiable)
    warned = [
        (label, d.reason)
        for label, d in results
        if d.action in (DecisionAction.NEEDS_CONFIRMATION, DecisionAction.LOG_ASYNC)
    ]

    if warned:
        console.print(
            f"[yellow]AgentShield: {len(warned)} item(s) flagged for review[/yellow]",
        )
        for label, reason in warned:
            console.print(f"  • {label}: {reason}")

    if blocked:
        console.print(
            f"[red]AgentShield BLOCKED {len(blocked)} item(s):[/red]",
        )
        for label, reason in blocked:
            console.print(f"  • {label}: {reason}")
        raise typer.Exit(code=1)


@app.command(context_settings={"ignore_unknown_options": True})
def hook(
    agent: str = typer.Option(
        "claude-code",
        "--agent",
        "-a",
        help="Requesting agent dialect: 'claude-code' (default), 'codex', or 'openclaw'.",
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
) -> None:
    """PreToolUse hook for Claude Code and OpenAI Codex.

    Reads the agent's PreToolUse payload as JSON on stdin, scans every package
    install in the pending shell command through the shared scan core, and emits
    the agent's block/allow contract:

    * BLOCK  → stdout JSON ``permissionDecision: "deny"`` (exit 0)
    * WARN   → ``"ask"`` on Claude Code (user is prompted); ``"deny"`` on Codex
               (which does not honor "ask" yet) — fail-closed either way
    * ALLOW  → exit 0 with no output (the call proceeds normally)

    Detected installs that cannot be verified (shell expansion, VCS URLs, remote
    requirements files, gem/go, untrusted conda channels, scanner errors) fail
    closed and are denied.

    Claude Code (.claude/settings.json)::

        {"hooks": {"PreToolUse": [{"matcher": "Bash",
          "hooks": [{"type": "command", "command": "agentshield hook"}]}]}}

    Codex (~/.codex/hooks.json; needs ``codex_hooks = true`` under [features])::

        {"hooks": {"PreToolUse": [{"matcher": "Bash",
          "hooks": [{"type": "command", "command": "agentshield hook --agent codex"}]}]}}
    """
    import sys

    from agentshield.core.config import Config
    from agentshield.integrations.claude_code import AGENTS, CLAUDE_CODE, run_hook

    agent_norm = agent.strip().lower()
    if agent_norm not in AGENTS:
        Console(stderr=True).print(
            f"[yellow]AgentShield hook: unknown --agent '{agent}', "
            f"defaulting to '{CLAUDE_CODE}'[/yellow]"
        )
        agent_norm = CLAUDE_CODE

    try:
        stdin_text = sys.stdin.read()
    except Exception:  # noqa: BLE001 — no stdin (e.g. a TTY) means nothing to scan
        stdin_text = ""

    cfg = Config.load(config)
    response = run_hook(stdin_text, agent=agent_norm, config=cfg)

    if response.stdout:
        sys.stdout.write(response.stdout)
    if response.stderr:
        sys.stderr.write(response.stderr)
    raise typer.Exit(code=response.exit_code)


@app.command()
def serve(
    mcp: bool = typer.Option(False, "--mcp", help="Run as MCP tool server (stdio transport)"),
    http: bool = typer.Option(False, "--http", help="Run as HTTP REST server on localhost"),
    socket: Path | None = typer.Option(
        None, "--socket", help="Unix socket path (default: ~/.agentshield/agentshield.sock)"
    ),
    port: int = typer.Option(8765, "--port", "-p", help="Port for HTTP server (default: 8765)"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    allowed_dirs: str | None = typer.Option(
        None,
        "--allowed-dirs",
        help=(
            "Comma-separated extra directories allowed for /scan-file and /sbom "
            "(e.g. /ci/workspace,/builds). Also accepted via AGENTSHIELD_ALLOWED_DIRS "
            "(colon-separated). /tmp and the system temp dir are always allowed."
        ),
    ),
) -> None:
    """Start the AgentShield daemon.

    \b
    agentshield serve              Unix socket JSON-RPC IPC server
    agentshield serve --mcp        MCP tool server on stdio
    agentshield serve --http       HTTP REST server on localhost:8765
    agentshield serve --http --port 9000
    agentshield serve --http --allowed-dirs /ci/workspace,/builds
    """
    import os
    import tempfile

    from agentshield.core.config import Config

    cfg = Config.load(config)
    shield = AgentShield(config=cfg)

    if mcp:
        import contextlib

        from agentshield.server.mcp import MCPServer

        server = MCPServer(shield)
        Console(stderr=True).print("[dim]AgentShield MCP server starting on stdio...[/dim]")
        with contextlib.suppress(KeyboardInterrupt):
            asyncio.run(server.run_stdio())
    elif http:
        from agentshield.server.http_server import HTTPServer

        # Build allowed-dirs list: standard defaults + CLI flag + env var extras
        extra_paths: list[Path] = []
        if allowed_dirs:
            for p in allowed_dirs.split(","):
                p = p.strip()
                if p:
                    extra_paths.append(Path(p))
        env_dirs = os.environ.get("AGENTSHIELD_ALLOWED_DIRS", "")
        if env_dirs:
            for p in env_dirs.split(":"):
                p = p.strip()
                if p:
                    extra_paths.append(Path(p))

        if extra_paths:
            seen: set[Path] = set()
            all_dirs: list[Path] = []
            for d in [
                Path.cwd(),
                Path.home(),
                Path("/tmp"),
                Path(tempfile.gettempdir()),
            ] + extra_paths:
                r = d.resolve()
                if r not in seen:
                    seen.add(r)
                    all_dirs.append(d)
            http_server = HTTPServer(shield, port=port, allowed_dirs=all_dirs)
        else:
            http_server = HTTPServer(shield, port=port)

        console.print(f"[dim]AgentShield HTTP server starting on http://127.0.0.1:{port} …[/dim]")
        try:
            asyncio.run(http_server.start())
        except KeyboardInterrupt:
            console.print("\n[dim]AgentShield HTTP server stopped.[/dim]")
    else:
        from agentshield.server.ipc import DEFAULT_SOCK_PATH, IPCServer

        sock_path = socket or DEFAULT_SOCK_PATH
        server_ipc = IPCServer(shield, sock_path=sock_path)
        console.print(f"[dim]AgentShield IPC server starting on {sock_path}...[/dim]")
        try:
            asyncio.run(server_ipc.start())
        except KeyboardInterrupt:
            console.print("\n[dim]AgentShield IPC server stopped.[/dim]")


def _print_diff_result(result: object) -> None:
    from agentshield.analyzers.diff_scanner import DiffScanResult

    r: DiffScanResult = result  # type: ignore[assignment]
    action = r.aggregate_decision.action
    color = {
        DecisionAction.ALLOW: "green",
        DecisionAction.LOG_ASYNC: "cyan",
        DecisionAction.NEEDS_CONFIRMATION: "yellow",
        DecisionAction.BLOCK: "red",
    }.get(action, "white")

    console.print(f"\n[bold {color}]{action.value}[/bold {color}] — {r.aggregate_decision.reason}")
    console.print(
        f"  Old: {r.old_path}  |  New: {r.new_path}\n"
        f"  Added: [cyan]{len(r.added_results)}[/cyan]"
        f"  |  Upgraded: [cyan]{len(r.upgraded_results)}[/cyan]"
        f"  |  Removed: [dim]{len(r.removed)}[/dim]"
        f"  |  Unchanged: [dim]{len(r.unchanged)}[/dim]\n"
    )

    if r.added_results or r.upgraded_results:
        table = Table(title="Changed Package Scan Results", show_header=True)
        table.add_column("Change", style="bold")
        table.add_column("Package", style="bold")
        table.add_column("Old Ver", style="dim")
        table.add_column("New Ver", style="dim")
        table.add_column("Status")
        table.add_column("Max Severity")
        table.add_column("Findings", justify="right", style="dim")

        def _add_rows(scan_results: list[ScanResult], change_label: str) -> None:
            for sr in scan_results:
                a = sr.decision.action
                sev = sr.max_severity.value
                status_color = {
                    DecisionAction.ALLOW: "green",
                    DecisionAction.LOG_ASYNC: "cyan",
                    DecisionAction.NEEDS_CONFIRMATION: "yellow",
                    DecisionAction.BLOCK: "red",
                }.get(a, "white")
                sev_color = {
                    "CRITICAL": "red",
                    "HIGH": "orange3",
                    "MEDIUM": "yellow",
                    "LOW": "cyan",
                    "INFO": "dim",
                    "NONE": "dim",
                }.get(sev, "white")
                table.add_row(
                    f"[cyan]{change_label}[/cyan]",
                    sr.request.package,
                    "—",
                    sr.request.version or "latest",
                    f"[{status_color}]{a.value}[/{status_color}]",
                    f"[{sev_color}]{sev}[/{sev_color}]",
                    str(len(sr.findings)),
                )

        _add_rows(r.added_results, "added")
        _add_rows(r.upgraded_results, "upgraded")
        console.print(table)

    if r.removed:
        console.print("\n[dim]Removed packages (not scanned):[/dim]")
        for d in r.removed:
            console.print(f"  • {d.package} ({d.version or 'any'}) [{d.ecosystem.value}]")


def _print_file_result(result: FileScanResult) -> None:
    action = result.aggregate_decision.action
    color = {
        DecisionAction.ALLOW: "green",
        DecisionAction.LOG_ASYNC: "cyan",
        DecisionAction.NEEDS_CONFIRMATION: "yellow",
        DecisionAction.BLOCK: "red",
    }.get(action, "white")

    console.print(
        f"\n[bold {color}]{action.value}[/bold {color}] — {result.aggregate_decision.reason}"
    )
    console.print(
        f"  File: {result.path}  |  Packages: {result.total_packages}"
        f"  |  Blocked: [red]{result.blocked}[/red]"
        f"  |  Warned: [yellow]{result.warned}[/yellow]"
        f"  |  Allowed: [green]{result.allowed}[/green]\n"
    )

    if not result.results:
        console.print("  [dim]No packages found.[/dim]")
        return

    table = Table(title="Package Scan Summary", show_header=True)
    table.add_column("Package", style="bold")
    table.add_column("Version", style="dim")
    table.add_column("Ecosystem", style="dim")
    table.add_column("Status")
    table.add_column("Max Severity")
    table.add_column("Findings", justify="right", style="dim")

    for r in result.results:
        req = r.request
        a = r.decision.action
        sev = r.max_severity.value
        status_color = {
            DecisionAction.ALLOW: "green",
            DecisionAction.LOG_ASYNC: "cyan",
            DecisionAction.NEEDS_CONFIRMATION: "yellow",
            DecisionAction.BLOCK: "red",
        }.get(a, "white")
        sev_color = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
            "NONE": "dim",
        }.get(sev, "white")
        table.add_row(
            req.package,
            req.version or "—",
            req.ecosystem.value,
            f"[{status_color}]{a.value}[/{status_color}]",
            f"[{sev_color}]{sev}[/{sev_color}]",
            str(len(r.findings)),
        )

    console.print(table)


def _print_transitive_results(results: list[ScanResult]) -> None:
    """Show a summary table for transitive dependency scan results."""
    console.print(f"\n[bold]Transitive Dependencies[/bold] ({len(results)} scanned)\n")

    table = Table(title="Transitive Dependency Scan", show_header=True)
    table.add_column("Package", style="bold")
    table.add_column("Ecosystem", style="dim")
    table.add_column("Status")
    table.add_column("Max Severity")
    table.add_column("Findings", justify="right", style="dim")

    for r in results:
        a = r.decision.action
        sev = r.max_severity.value
        status_color = {
            DecisionAction.ALLOW: "green",
            DecisionAction.LOG_ASYNC: "cyan",
            DecisionAction.NEEDS_CONFIRMATION: "yellow",
            DecisionAction.BLOCK: "red",
        }.get(a, "white")
        sev_color = {
            "CRITICAL": "red",
            "HIGH": "orange3",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
            "NONE": "dim",
        }.get(sev, "white")
        table.add_row(
            r.request.package,
            r.request.ecosystem.value,
            f"[{status_color}]{a.value}[/{status_color}]",
            f"[{sev_color}]{sev}[/{sev_color}]",
            str(len(r.findings)),
        )

    console.print(table)


def _print_result(result: ScanResult, wall_ms: int | None = None) -> None:
    action = result.decision.action
    color = {
        DecisionAction.ALLOW: "green",
        DecisionAction.LOG_ASYNC: "cyan",
        DecisionAction.NEEDS_CONFIRMATION: "yellow",
        DecisionAction.BLOCK: "red",
    }.get(action, "white")

    duration_display = (
        f"{wall_ms}ms (wall)" if wall_ms is not None else f"{result.scan_duration_ms}ms"
    )
    console.print(f"\n[bold {color}]{action.value}[/bold {color}] — {result.decision.reason}")
    trust_display = (
        f"  |  Trust: {result.trust_score}/100 ({result.trust_label})"
        if result.trust_score is not None
        else ""
    )
    console.print(
        f"  Cache hit: {result.cache_hit}  |  Duration: {duration_display}"
        f"  |  Max severity: {result.max_severity.value}{trust_display}\n"
    )

    if result.findings:
        table = Table(title="Findings", show_header=True)
        table.add_column("Rule", style="dim")
        table.add_column("Severity")
        table.add_column("CVSS", justify="right", style="dim")
        table.add_column("Title")
        table.add_column("Source", style="dim")
        table.add_column("Remediation", style="dim")
        for f in result.findings:
            sev_color = {
                "CRITICAL": "red",
                "HIGH": "orange3",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "dim",
            }.get(f.severity.value, "white")
            cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—"
            table.add_row(
                f.rule_id,
                f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                cvss_str,
                f.title,
                f.source,
                f.remediation or "—",
            )
        console.print(table)
    else:
        console.print("  [dim]No findings.[/dim]")

    if result.transitive_results:
        _print_transitive_results(result.transitive_results)


# ── enforcement layer (shim / execve / proxy) ────────────────────────────────

shim_app = typer.Typer(name="shim", help="Manage the PATH-shim enforcement baseline.")
app.add_typer(shim_app)


@shim_app.command("install")
def shim_install(
    directory: Path | None = typer.Option(
        None, "--dir", "-d", help="Shim directory (default: ~/.agentshield/shim)"
    ),
) -> None:
    """Install PATH-shim wrappers for every managed package-manager binary."""
    from agentshield.enforce import shim

    shim_dir, installed = shim.install(directory)
    console.print(f"[green]Installed {len(installed)} shim(s) in {shim_dir}[/green]")
    console.print("Add this to your shell profile so the shims take precedence:")
    console.print(f"  [cyan]{shim.path_export_line(shim_dir)}[/cyan]")
    console.print(
        "[dim]Note: covers PATH-resolved invocations. For absolute-path calls "
        "(/usr/bin/pip) also enable the execve interceptor (Linux).[/dim]"
    )


@shim_app.command("uninstall")
def shim_uninstall(
    directory: Path | None = typer.Option(
        None, "--dir", "-d", help="Shim directory (default: ~/.agentshield/shim)"
    ),
) -> None:
    """Remove AgentShield PATH-shim wrappers."""
    from agentshield.enforce import shim

    removed = shim.uninstall(directory)
    console.print(f"[green]Removed {len(removed)} shim(s).[/green]")


@app.command("enforce-build")
def enforce_build(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output .so path (default: ~/.agentshield/libagentshield_exec.so)",
    ),
) -> None:
    """Compile the Linux execve interceptor (LD_PRELOAD library)."""
    from agentshield.enforce import execve

    try:
        so_path = execve.build(output)
    except RuntimeError as exc:
        console.print(f"[red]Could not build execve interceptor:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Built {so_path}[/green]")
    console.print("Activate it for a session with:")
    console.print(f"  [cyan]{execve.preload_env_line(so_path)}[/cyan]")


@app.command("proxy")
def proxy(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address"),
    port: int = typer.Option(8799, "--port", "-p", help="Bind port"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    transitive: bool = typer.Option(
        True, "--transitive/--no-transitive", help="Also scan resolved transitive deps"
    ),
    print_env: bool = typer.Option(
        False,
        "--print-env",
        help="Print the export lines to route managers through the proxy and exit",
    ),
) -> None:
    """Run the scanning index proxy — the primary enforcement gate.

    Route pip/uv and npm/yarn/pnpm/bun through it by exporting the env it prints
    on startup (or `agentshield proxy --print-env`), e.g.::

        export PIP_INDEX_URL=http://127.0.0.1:8799/simple/
        export npm_config_registry=http://127.0.0.1:8799/npm/
    """
    from agentshield.core.config import Config
    from agentshield.enforce import proxy as proxy_mod

    if print_env:
        for line in proxy_mod.proxy_export_lines(host, port):
            print(line)
        return

    cfg = Config.load(config)
    console.print(f"[cyan]AgentShield index proxy on http://{host}:{port}[/cyan]  (Ctrl-C to stop)")
    console.print("[dim]Route managers through the proxy in another shell:[/dim]")
    for line in proxy_mod.proxy_export_lines(host, port):
        console.print(f"  [green]{line}[/green]")
    proxy_mod.serve(host=host, port=port, config=cfg, transitive=transitive)


@app.command("enforce-env")
def enforce_env(
    host: str = typer.Option("127.0.0.1", "--host", help="Proxy bind address"),
    port: int = typer.Option(8799, "--port", "-p", help="Proxy bind port"),
    shim_dir: Path | None = typer.Option(None, "--shim-dir", help="Shim directory"),
) -> None:
    """Print the full defense-in-depth setup: proxy env (primary) + shim PATH +
    execve preload (secondary/baseline)."""
    from agentshield.enforce import execve, shim
    from agentshield.enforce import proxy as proxy_mod

    print("# 1. Primary gate — index proxy (run `agentshield proxy` first):")
    for line in proxy_mod.proxy_export_lines(host, port):
        print(line)
    print("\n# 2. Baseline — PATH shim (run `agentshield shim install` first):")
    target = shim_dir if shim_dir else shim.default_shim_dir()
    print(shim.path_export_line(target))
    print("\n# 3. Absolute-path coverage — execve interceptor (run `agentshield enforce-build`):")
    so_name = "libagentshield_exec.dylib" if execve.is_macos() else "libagentshield_exec.so"
    so_path = Path.home() / ".agentshield" / so_name
    print(execve.preload_env_line(so_path))


if __name__ == "__main__":
    app()
