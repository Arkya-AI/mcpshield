from __future__ import annotations

import asyncio
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from mcpshield import __version__
from mcpshield.models import Severity
from mcpshield.scanner.engine import Scanner

app = typer.Typer(
    name="mcpshield",
    help="MCP Security Scanner — audit your MCP server configurations.",
    add_completion=False,
    no_args_is_help=True,
)

err_console = Console(stderr=True)

_SEVERITY_RANK: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


class OutputFormat(str, Enum):
    console = "console"
    json = "json"


class SeverityThreshold(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


def _build_scanner() -> Scanner:
    """Build a Scanner pre-loaded with all registered checks.

    Checks register themselves via mcpshield.checks.get_all_checks() when that
    helper is available.  Falls back to an empty scanner if the checks package
    has not yet been populated.
    """
    scanner = Scanner()
    try:
        from mcpshield import checks as _checks_pkg

        if hasattr(_checks_pkg, "get_all_checks"):
            for check in _checks_pkg.get_all_checks():
                scanner.register(check)
    except Exception:
        pass
    return scanner


def _filter_findings(results, threshold: str):
    rank = _SEVERITY_RANK[threshold]
    return [
        result.model_copy(
            update={
                "findings": [
                    f for f in result.findings if _SEVERITY_RANK[f.severity.value] <= rank
                ]
            }
        )
        for result in results
    ]


def _emit(results, fmt: OutputFormat, output: Optional[Path]) -> None:
    if fmt == OutputFormat.json:
        from mcpshield.reporter.json_report import generate_json_report

        content = generate_json_report(results)
        if output:
            output.write_text(content, encoding="utf-8")
            err_console.print(f"[green]Report written to:[/green] {output}")
        else:
            print(content)
    else:
        from mcpshield.reporter.console import print_scan_results
        import mcpshield.reporter.console as _cr

        if output:
            file_console = Console(file=output.open("w", encoding="utf-8"), highlight=False)
            original = _cr.console
            _cr.console = file_console
            try:
                print_scan_results(results)
            finally:
                _cr.console = original
                file_console.file.close()
            err_console.print(f"[green]Report written to:[/green] {output}")
        else:
            print_scan_results(results)


@app.command()
def scan(
    config_path: Path = typer.Argument(..., help="Path to MCP config JSON file."),
    format: OutputFormat = typer.Option(
        OutputFormat.console, "--format", "-f", help="Output format (console|json)."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write report to file instead of stdout."
    ),
    severity_threshold: SeverityThreshold = typer.Option(
        SeverityThreshold.info,
        "--severity-threshold",
        "-s",
        help="Minimum severity level to show (critical|high|medium|low|info).",
    ),
) -> None:
    """Scan an MCP config file for security issues."""
    from mcpshield.cli.config_parser import parse_config_file, ConfigParseError

    try:
        config = parse_config_file(config_path)
    except ConfigParseError as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if not config.servers:
        err_console.print("[yellow]Warning:[/yellow] No MCP servers found in config.")
        raise typer.Exit(code=0)

    err_console.print(
        f"[cyan]Scanning [bold]{len(config.servers)}[/bold] server(s) "
        f"from [bold]{config_path}[/bold]...[/cyan]"
    )

    scanner = _build_scanner()
    results = asyncio.run(scanner.scan_config(config))
    results = _filter_findings(results, severity_threshold.value)

    _emit(results, format, output)

    any_critical = any(
        f.severity == Severity.CRITICAL for r in results for f in r.findings
    )
    raise typer.Exit(code=2 if any_critical else 0)


@app.command(name="scan-url")
def scan_url(
    url: str = typer.Argument(..., help="URL of the remote MCP server to scan."),
    name: str = typer.Option("remote", "--name", "-n", help="Logical name for the server."),
    format: OutputFormat = typer.Option(
        OutputFormat.console, "--format", "-f", help="Output format (console|json)."
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write report to file instead of stdout."
    ),
    severity_threshold: SeverityThreshold = typer.Option(
        SeverityThreshold.info,
        "--severity-threshold",
        "-s",
        help="Minimum severity level to show (critical|high|medium|low|info).",
    ),
) -> None:
    """Scan a remote MCP server by URL."""
    from mcpshield.cli.config_parser import make_single_server_config

    config = make_single_server_config(url=url, name=name)
    err_console.print(f"[cyan]Scanning remote server [bold]{url}[/bold]...[/cyan]")

    scanner = _build_scanner()
    results = asyncio.run(scanner.scan_config(config))
    results = _filter_findings(results, severity_threshold.value)

    _emit(results, format, output)

    any_critical = any(
        f.severity == Severity.CRITICAL for r in results for f in r.findings
    )
    raise typer.Exit(code=2 if any_critical else 0)


@app.command()
def version() -> None:
    """Show mcpshield version."""
    typer.echo(f"mcpshield {__version__}")


if __name__ == "__main__":
    app()
