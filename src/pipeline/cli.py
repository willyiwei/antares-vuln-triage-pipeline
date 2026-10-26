"""CLI entry point for the AnTAres Vulnerability Triage Pipeline."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config import PipelineConfig
from .pipeline import TriagePipeline
from .reporting import generate_summary_report

console = Console()


@click.group()
def main() -> None:
    """AnTAres Vulnerability Triage Pipeline — AI-powered security scanning with governance."""
    pass


@main.command()
@click.option("--repo", "-r", required=True, help="Git repository URL or local path to scan")
@click.option("--branch", "-b", default=None, help="Git branch to scan (default: default branch)")
@click.option("--config", "-c", default="config/pipeline.yaml", help="Path to pipeline config YAML")
@click.option("--output", "-o", default="./reports", help="Output directory for reports")
@click.option("--mock/--no-mock", default=True, help="Use mock data when AnTAres API is unavailable")
@click.option("--dashboard/--no-dashboard", default=False, help="Start the web dashboard after scan")
def scan(repo: str, branch: str, config: str, output: str, mock: bool, dashboard: bool) -> None:
    """Run a vulnerability scan and triage cycle."""
    cfg = PipelineConfig.load(config)
    cfg.output_dir = Path(output)

    if mock:
        console.print("[yellow]⚠ Mock mode enabled — using simulated AnTAres data[/yellow]")

    pipeline = TriagePipeline(cfg)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running AnTAres scan...", total=None)
        result = asyncio.run(pipeline.run_scan(repo, branch=branch))
        progress.update(task, description="Scan complete — running governance triage")

    # Print summary
    console.print()
    console.print(f"[bold green]Scan Complete:[/bold green] {result.scan_id}")
    console.print(f"Repository: {result.repo_url or 'local'}")
    console.print(f"Total Findings: {result.total_findings}")

    # Severity table
    table = Table(title="Findings by Severity")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = result.findings_by_severity.get(sev, 0)
        if count > 0:
            color = {"critical": "red", "high": "yellow", "medium": "blue", "low": "green", "info": "dim"}[sev]
            table.add_row(f"[{color}]{sev.capitalize()}[/{color}]", str(count))
    console.print(table)

    # Governance summary
    gov = result.governance_summary
    console.print(f"\n[bold]Governance:[/bold]")
    console.print(f"  Auto-Accepted: {gov.get('auto_accepted', 0)}")
    console.print(f"  Auto-Rejected: {gov.get('auto_rejected', 0)}")
    console.print(f"  Human Review:  {gov.get('human_review_required', 0)}")
    console.print(f"  Escalated:     {gov.get('escalated', 0)}")

    # Write summary report
    report_path = Path(output) / "summary.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(generate_summary_report(result))
    console.print(f"\n[green]✓ Reports written to {output}[/green]")

    if dashboard:
        console.print("[cyan]Starting dashboard...[/cyan]")
        asyncio.run(start_dashboard(cfg))


@main.command()
@click.option("--host", default="127.0.0.1", help="Dashboard host")
@click.option("--port", default=8181, type=int, help="Dashboard port")
def dashboard(host: str, port: int) -> None:
    """Start the web dashboard."""
    console.print(f"[cyan]Starting dashboard at http://{host}:{port}[/cyan]")
    asyncio.run(start_dashboard(PipelineConfig()))


async def start_dashboard(config: PipelineConfig) -> None:
    """Start the FastAPI dashboard server."""
    from .dashboard_app import create_app

    app = create_app(config)
    import uvicorn

    uvicorn.run(
        app,
        host=config.dashboard.get("host", "127.0.0.1"),
        port=config.dashboard.get("port", 8181),
        log_level="info",
    )


if __name__ == "__main__":
    main()
