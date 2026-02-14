"""Command-line interface for code security scanner."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich.panel import Panel

from .scanner import Scanner
from .models import Severity


console = Console()


@click.command()
@click.argument("directory", type=click.Path(exists=True), default=".")
@click.option(
    "--format", "-f",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    help="Output format"
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    help="Output file path"
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "all"]),
    default="all",
    help="Minimum severity to report"
)
@click.option(
    "--ai-analysis",
    is_flag=True,
    help="Enable AI-powered analysis (requires API key)"
)
def main(directory: str, format: str, output: str, severity: str, ai_analysis: bool):
    """Scan a directory for security issues.
    
    DIRECTORY: Path to directory to scan (default: current directory)
    """
    console.print(f"[bold blue]🔍 Scanning {directory}...[/bold blue]\n")
    
    scanner = Scanner()
    result = scanner.scan_directory(directory)
    
    # Filter by severity if needed
    if severity != "all":
        severity_level = Severity.CRITICAL if severity == "critical" else \
                        Severity.HIGH if severity == "high" else \
                        Severity.MEDIUM if severity == "medium" else \
                        Severity.LOW
        result.issues = [i for i in result.issues if i.severity == severity_level]
    
    # Output results
    if format == "json":
        output_data = result.to_dict()
        output_json = json.dumps(output_data, indent=2)
        
        if output:
            Path(output).write_text(output_json)
            console.print(f"[green]Results saved to {output}[/green]")
        else:
            console.print(output_json)
    elif format == "text":
        _print_text_output(result)
    else:
        console.print("[yellow]SARIF format not yet implemented[/yellow]")
        _print_text_output(result)
    
    # Exit with appropriate code
    if result.critical_count > 0 or result.high_count > 0:
        sys.exit(1)
    sys.exit(0)


def _print_text_output(result):
    """Print results in text format."""
    # Summary
    console.print("\n[bold]📊 Scan Summary[/bold]")
    console.print(f"  Files scanned: {result.files_scanned}")
    console.print(f"  Issues found: {len(result.issues)}")
    console.print(f"    🔴 Critical: {result.critical_count}")
    console.print(f"    🟠 High: {result.high_count}")
    console.print(f"    🟡 Medium: {result.medium_count}")
    console.print(f"    🔵 Low: {result.low_count}")
    console.print(f"  Scan duration: {result.scan_duration_seconds:.2f}s\n")
    
    if not result.issues:
        console.print("[green]✅ No security issues found![/green]")
        return
    
    # Issues table
    table = Table(title="Security Issues", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("Message", style="white")
    table.add_column("File", style="dim")
    table.add_column("Line", justify="right")
    
    for issue in result.issues:
        severity_icon = {
            Severity.CRITICAL: "[red]🔴 CRITICAL[/red]",
            Severity.HIGH: "[orange]🟠 HIGH[/orange]",
            Severity.MEDIUM: "[yellow]🟡 MEDIUM[/yellow]",
            Severity.LOW: "[blue]🔵 LOW[/blue]",
        }.get(issue.severity, "⚪")
        
        table.add_row(
            severity_icon,
            issue.issue_type.value,
            issue.message,
            issue.file_path,
            str(issue.line_number)
        )
    
    console.print(table)
    
    # Show details for critical issues
    critical_issues = [i for i in result.issues if i.severity == Severity.CRITICAL]
    if critical_issues:
        console.print("\n[bold red]🚨 Critical Issues Details[/bold red]")
        for issue in critical_issues[:5]:  # Show first 5
            console.print(f"\n[red]• {issue.message}[/red]")
            console.print(f"  File: {issue.file_path}:{issue.line_number}")
            if issue.remediation:
                console.print(f"  [green]Fix: {issue.remediation}[/green]")


if __name__ == "__main__":
    main()
