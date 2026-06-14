from __future__ import annotations

import asyncio
import time
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
    DecisionAction,
    Ecosystem,
    FileScanResult,
    ScanRequest,
    ScanResult,
)
from agentshield.core.scanner import AgentShield

app = typer.Typer(name="agentshield", help="Security layer for AI agent package installations")
console = Console()


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
            console.print(text)
    elif fmt == "html":
        text = render_html(report)
        if output:
            output.write_text(text)
            console.print(f"[green]HTML report written to {output}[/green]")
        else:
            console.print(text)
    elif fmt == "markdown":
        text = render_markdown(report)
        if output:
            output.write_text(text)
            console.print(f"[green]Markdown report written to {output}[/green]")
        else:
            console.print(text)
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
        stats = asyncio.run(sc.stats())
        console.print(f"[bold]Cache stats[/bold] — {cfg.cache.db_path}")
        console.print(f"  Scan results : {stats['live']} live / {stats['expired']} expired")
        console.print(f"  CVE mirror   : {stats.get('cve_mirror', 0)} entries")
        console.print(f"  Malicious DB : {stats.get('malicious_packages', 0)} packages")

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
        result = asyncio.run(shield.ascan_file(path))

    _print_file_result(result)

    if result.aggregate_decision.action == DecisionAction.BLOCK:
        raise typer.Exit(code=1)


@app.command()
def serve(
    mcp: bool = typer.Option(False, "--mcp", help="Run as MCP tool server (stdio transport)"),
    socket: Path | None = typer.Option(
        None, "--socket", help="Unix socket path (default: ~/.agentshield/agentshield.sock)"
    ),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
) -> None:
    """Start the AgentShield daemon.

    \b
    agentshield serve           Unix socket JSON-RPC IPC server
    agentshield serve --mcp     MCP tool server on stdio (for MCP-compatible agents)
    """
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
    else:
        from agentshield.server.ipc import DEFAULT_SOCK_PATH, IPCServer

        sock_path = socket or DEFAULT_SOCK_PATH
        server_ipc = IPCServer(shield, sock_path=sock_path)
        console.print(f"[dim]AgentShield IPC server starting on {sock_path}...[/dim]")
        try:
            asyncio.run(server_ipc.start())
        except KeyboardInterrupt:
            console.print("\n[dim]AgentShield IPC server stopped.[/dim]")


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
    console.print(
        f"  Cache hit: {result.cache_hit}  |  Duration: {duration_display}"
        f"  |  Max severity: {result.max_severity.value}\n"
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


if __name__ == "__main__":
    app()
