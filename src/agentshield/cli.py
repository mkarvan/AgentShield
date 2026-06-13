from __future__ import annotations

import time
from pathlib import Path

import typer
from rich.console import Console
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

    shield = AgentShield(config_path=config)
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
) -> None:
    """Manage the local scan cache."""
    import asyncio

    from agentshield.core.cache import ScanCache
    from agentshield.core.config import Config

    cfg = Config.load()
    sc = ScanCache(cfg.cache)

    if action == "clear":
        deleted = asyncio.run(sc.clear())
        console.print(f"[green]Cleared {deleted} cached entries.[/green]")
    elif action == "stats":
        stats = asyncio.run(sc.stats())
        console.print(f"[bold]Cache stats[/bold] — {cfg.cache.db_path}")
        console.print(f"  Total entries : {stats['total']}")
        console.print(f"  Live entries  : {stats['live']}")
        console.print(f"  Expired       : {stats['expired']}")
    else:
        console.print(f"[yellow]cache {action} not yet implemented.[/yellow]")


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
