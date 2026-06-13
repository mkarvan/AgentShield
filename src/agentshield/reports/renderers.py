"""Report renderers — convert a PostureReport to various output formats."""

from __future__ import annotations

from pathlib import Path

from agentshield.reports.models import PostureReport


def render_json(report: PostureReport) -> str:
    """Return the report serialised as a pretty-printed JSON string."""
    return report.model_dump_json(indent=2)


def render_html(report: PostureReport) -> str:
    """Render the report as a self-contained HTML page (Jinja2 template)."""
    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError as exc:
        raise RuntimeError("jinja2 is required for HTML reports: pip install jinja2") from exc

    templates_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)
    template = env.get_template("posture_report.html.jinja2")
    return template.render(report=report)


def render_markdown(report: PostureReport) -> str:
    """Render the report as a Markdown document."""
    lines: list[str] = []
    ts = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")

    lines += [
        "# AgentShield Posture Report",
        "",
        f"> Generated: {ts}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Risk score | **{report.risk_score}/100 — {report.risk_label}** |",
        f"| Packages scanned | {report.packages_scanned} |",
        f"| Critical findings | {report.critical_count} |",
        f"| High findings | {report.high_count} |",
        f"| Medium findings | {report.medium_count} |",
        f"| Low findings | {report.low_count} |",
        "",
    ]

    if report.critical_findings:
        lines += ["## Critical Findings", ""]
        for pkg, f in report.critical_findings:
            cvss = f" | CVSS {f.cvss_score:.1f}" if f.cvss_score is not None else ""
            lines += [
                f"### [{f.rule_id}] {f.title}",
                "",
                f"**Package:** `{pkg}`  **Severity:** CRITICAL{cvss}  **Source:** {f.source}",
                "",
            ]
            if f.description:
                lines += [f.description, ""]
            if f.remediation:
                lines += [f"**Fix:** {f.remediation}", ""]

    if report.high_findings:
        lines += ["## High Findings", ""]
        for pkg, f in report.high_findings:
            cvss = f" | CVSS {f.cvss_score:.1f}" if f.cvss_score is not None else ""
            lines += [
                f"### [{f.rule_id}] {f.title}",
                "",
                f"**Package:** `{pkg}`  **Severity:** HIGH{cvss}  **Source:** {f.source}",
                "",
            ]
            if f.description:
                lines += [f.description, ""]
            if f.remediation:
                lines += [f"**Fix:** {f.remediation}", ""]

    if report.tools:
        lines += ["## Attack Surface", ""]
        high_tools = [t.name for t in report.tools if t.risk_level == "high"]
        med_tools = [t.name for t in report.tools if t.risk_level == "medium"]
        low_tools = [t.name for t in report.tools if t.risk_level == "low"]
        lines += [
            f"Registered tools: **{len(report.tools)}**",
            "",
        ]
        if high_tools:
            lines += [f"- High-risk: {', '.join(f'`{t}`' for t in high_tools)}"]
        if med_tools:
            lines += [f"- Medium-risk: {', '.join(f'`{t}`' for t in med_tools)}"]
        if low_tools:
            lines += [f"- Low-risk: {', '.join(f'`{t}`' for t in low_tools)}"]
        lines += [""]

    if report.env_vars_detected:
        lines += [
            "### Sensitive Environment Variables",
            "",
            f"{', '.join(f'`{v}`' for v in report.env_vars_detected)} detected (values not read)",
            "",
        ]

    if report.async_log_entries:
        lines += [
            "## Async Report Log (last 24 h)",
            "",
            f"{len(report.async_log_entries)} package(s) installed without real-time check.",
        ]
        if report.async_log_medium_plus_count:
            lines += [
                f"⚠ {report.async_log_medium_plus_count} with MEDIUM+ findings — review recommended."
            ]
        lines += [""]
        lines += [
            "| Package | Ecosystem | Severity | Logged |",
            "|---------|-----------|----------|--------|",
        ]
        for entry in report.async_log_entries:
            sevs = ", ".join(f.severity.value for f in entry.findings) if entry.findings else "—"
            logged = entry.logged_at.strftime("%Y-%m-%d %H:%M")
            lines += [f"| `{entry.package}` | {entry.ecosystem} | {sevs} | {logged} |"]
        lines += [""]

    lines += ["---", "", "*AgentShield v0.1.0*"]
    return "\n".join(lines)


def render_terminal(report: PostureReport) -> None:
    """Print the report to the terminal using Rich."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()

    _SEV_COLOR = {
        "CRITICAL": "bold red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "blue",
        "NONE": "dim",
    }
    _LABEL_COLOR = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange3",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
    }

    ts = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    label_color = _LABEL_COLOR.get(report.risk_label, "white")

    # Header panel
    header = Text()
    header.append("Risk Score: ", style="bold")
    header.append(f"{report.risk_score}/100 — {report.risk_label}", style=label_color)
    header.append(f"  |  Generated: {ts}", style="dim")
    console.print(
        Panel(header, title="[bold]AgentShield Posture Report[/bold]", border_style="blue")
    )

    # Summary counts
    summary = Table.grid(padding=(0, 4))
    summary.add_column()
    summary.add_column()
    summary.add_column()
    summary.add_column()
    summary.add_column()
    summary.add_row(
        f"[dim]Packages scanned:[/dim] [bold]{report.packages_scanned}[/bold]",
        f"[bold red]CRITICAL: {report.critical_count}[/bold red]",
        f"[orange3]HIGH: {report.high_count}[/orange3]",
        f"[yellow]MEDIUM: {report.medium_count}[/yellow]",
        f"[green]LOW: {report.low_count}[/green]",
    )
    console.print(summary)
    console.print()

    # Critical findings
    if report.critical_findings:
        console.rule("[bold red]CRITICAL FINDINGS[/bold red]")
        for pkg, f in report.critical_findings:
            cvss = f"CVSS {f.cvss_score:.1f}  " if f.cvss_score is not None else ""
            console.print(f"  [bold red][CRITICAL][/bold red] {f.rule_id} — {f.title}")
            console.print(f"    Package: [bold]{pkg}[/bold]  {cvss}Source: {f.source}")
            if f.description:
                console.print(f"    [dim]{f.description[:200]}[/dim]")
            if f.remediation:
                console.print(f"    [green]Fix: {f.remediation}[/green]")
            console.print()

    # High findings
    if report.high_findings:
        console.rule("[orange3]HIGH FINDINGS[/orange3]")
        for pkg, f in report.high_findings:
            cvss = f"CVSS {f.cvss_score:.1f}  " if f.cvss_score is not None else ""
            console.print(f"  [orange3][HIGH][/orange3] {f.rule_id} — {f.title}")
            console.print(f"    Package: [bold]{pkg}[/bold]  {cvss}Source: {f.source}")
            if f.remediation:
                console.print(f"    [green]Fix: {f.remediation}[/green]")
            console.print()

    # Attack surface
    console.rule("[dim]ATTACK SURFACE[/dim]")
    if report.tools:
        high_t = [t.name for t in report.tools if t.risk_level == "high"]
        med_t = [t.name for t in report.tools if t.risk_level == "medium"]
        console.print(f"  [bold]Registered tools:[/bold] {len(report.tools)}")
        if high_t:
            console.print(f"  [red]High-risk:[/red] {', '.join(high_t)}")
        if med_t:
            console.print(f"  [yellow]Medium-risk:[/yellow] {', '.join(med_t)}")
    else:
        console.print("  [dim]No tools registered.[/dim]")

    if report.env_vars_detected:
        console.print("\n  [bold]Sensitive env vars:[/bold]", end="  ")
        for v in report.env_vars_detected:
            console.print(f"[dim]{v}[/dim] [green]✓[/green]", end="  ")
        console.print()
    console.print()

    # Async log
    console.rule("[dim]ASYNC REPORT LOG (last 24 h)[/dim]")
    if report.async_log_entries:
        console.print(
            f"  {len(report.async_log_entries)} package(s) installed without real-time check "
            f"(async_report mode)"
        )
        if report.async_log_medium_plus_count:
            console.print(
                f"  [yellow]{report.async_log_medium_plus_count} with MEDIUM+ findings — "
                f"review recommended[/yellow]"
            )
        tbl = Table(show_header=True, header_style="dim")
        tbl.add_column("Package")
        tbl.add_column("Ecosystem", style="dim")
        tbl.add_column("Findings")
        tbl.add_column("Logged", style="dim")
        for entry in report.async_log_entries:
            sevs = (
                " ".join(
                    f"[{_SEV_COLOR.get(f.severity.value, 'white')}]{f.severity.value}[/]"
                    for f in entry.findings
                )
                if entry.findings
                else "[dim]none[/dim]"
            )
            tbl.add_row(
                entry.package,
                entry.ecosystem,
                sevs,
                entry.logged_at.strftime("%Y-%m-%d %H:%M"),
            )
        console.print(tbl)
    else:
        console.print("  [dim]No async-report log entries in the last 24 hours.[/dim]")
    console.print()
