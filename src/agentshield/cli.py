from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from agentshield.core.models import DecisionAction, Ecosystem, ScanRequest, ScanResult
from agentshield.core.scanner import AgentShield

app = typer.Typer(name="agentshield", help="Security layer for AI agent package installations")
console = Console()


@app.command()
def scan(
    package: str = typer.Argument(..., help="Package name (optionally with ==version, e.g. requests==2.28.0)"),
    ecosystem: Ecosystem = typer.Option(Ecosystem.PYPI, "--ecosystem", "-e", help="pypi|npm|cargo"),
    config: Path | None = typer.Option(None, "--config", "-c", help="Path to config.toml"),
    deep: bool = typer.Option(False, "--deep", help="Run static analysis in addition to CVE lookups"),
    offline: bool = typer.Option(False, "--offline", help="Use only local DB — no network calls"),
) -> None:
    """Scan a package for security vulnerabilities."""
    name, _, version = package.partition("==")
    request = ScanRequest(
        package=name.strip(),
        version=version.strip() or None,
        ecosystem=ecosystem,
        source="cli",
        deep=deep,
    )

    from agentshield.core.config import Config

    cfg = Config.load(config)
    if offline:
        cfg = cfg.model_copy(update={"offline": True})

    shield = AgentShield(config=cfg)
    t0 = time.monotonic()
    result = shield.scan(request)
    wall_ms = int((time.monotonic() - t0) * 1000)

    _print_result(result, wall_ms)

    if result.decision.action == DecisionAction.BLOCK:
        raise typer.Exit(code=1)


@app.command()
def posture(
    output: Path | None = typer.Option(None, "--output", "-o"),
    fmt: str = typer.Option("terminal", "--format", "-f", help="terminal|json|html|markdown"),
) -> None:
    """Generate a security posture report for the current agent environment."""
    console.print("[yellow]Posture check not yet implemented — coming in Phase 4.[/yellow]")


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
    from agentshield.core.config import Config
    from agentshield.databases.warm import warm_cache

    real_cfg = cfg  # type: ignore[assignment]

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
                progress.update(overall, advance=1, description=f"[green]{ecosystem} done ({count} advisories)")

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


def _print_result(result: ScanResult, wall_ms: int | None = None) -> None:
    action = result.decision.action
    color = {
        DecisionAction.ALLOW: "green",
        DecisionAction.LOG_ASYNC: "cyan",
        DecisionAction.NEEDS_CONFIRMATION: "yellow",
        DecisionAction.BLOCK: "red",
    }.get(action, "white")

    duration_display = f"{wall_ms}ms (wall)" if wall_ms is not None else f"{result.scan_duration_ms}ms"
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


if __name__ == "__main__":
    app()
