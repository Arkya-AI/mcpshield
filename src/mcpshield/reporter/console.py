from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich import box

from mcpshield.models import ScanResult, SecurityFinding, SecurityGrade, Severity

console = Console()

_GRADE_STYLE: dict[SecurityGrade, str] = {
    SecurityGrade.A: "bold green",
    SecurityGrade.B: "green",
    SecurityGrade.C: "yellow",
    SecurityGrade.D: "red",
    SecurityGrade.F: "bold red",
}

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "grey70",
}

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


def _grade_panel(result: ScanResult) -> Panel:
    style = _GRADE_STYLE[result.grade]
    grade_text = Text(result.grade.value, style=f"{style} bold", justify="center")
    grade_text.stylize("font-size: 3em")
    content = Text(justify="center")
    content.append(f"{result.grade.value}\n", style=f"{style} bold")
    content.append(f"Score: {result.score}/100\n", style="white")
    content.append(f"Server: {result.server_name}", style="dim white")
    return Panel(content, title="[bold]Security Grade[/bold]", border_style=style, expand=False)


def _findings_table(findings: list[SecurityFinding], severity: Severity) -> Table | None:
    filtered = [f for f in findings if f.severity == severity]
    if not filtered:
        return None

    style = _SEVERITY_STYLE[severity]
    table = Table(
        box=box.ROUNDED,
        border_style=style,
        show_header=True,
        header_style=f"bold {style}",
        expand=True,
        padding=(0, 1),
    )
    table.add_column("Check ID", style="dim", no_wrap=True, width=18)
    table.add_column("Title", style="bold white", width=28)
    table.add_column("Description", style="white")
    table.add_column("Remediation", style="dim white")

    for finding in filtered:
        table.add_row(
            finding.check_id,
            finding.title,
            finding.description,
            finding.remediation,
        )

    return table


def _summary_table(results: list[ScanResult]) -> Table:
    table = Table(
        title="Scan Summary",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold white",
        expand=True,
    )
    table.add_column("Server", style="bold white", no_wrap=True)
    table.add_column("Grade", justify="center", no_wrap=True)
    table.add_column("Score", justify="right", no_wrap=True)
    for sev in _SEVERITY_ORDER:
        table.add_column(sev.value.capitalize(), justify="right", style=_SEVERITY_STYLE[sev], no_wrap=True)

    for result in results:
        counts = {sev: sum(1 for f in result.findings if f.severity == sev) for sev in _SEVERITY_ORDER}
        grade_style = _GRADE_STYLE[result.grade]
        table.add_row(
            result.server_name,
            Text(result.grade.value, style=f"bold {grade_style}"),
            str(result.score),
            *[str(counts[sev]) if counts[sev] > 0 else "[dim]0[/dim]" for sev in _SEVERITY_ORDER],
        )

    return table


def _overall_recommendation(results: list[ScanResult]) -> str:
    critical_count = sum(
        1 for r in results for f in r.findings if f.severity == Severity.CRITICAL
    )
    worst_grade = min(results, key=lambda r: r.score).grade if results else SecurityGrade.A

    if worst_grade == SecurityGrade.F or critical_count > 0:
        return (
            "[bold red]Action required:[/bold red] Critical security issues detected. "
            "Do not deploy to production until resolved."
        )
    if worst_grade == SecurityGrade.D:
        return (
            "[red]High risk:[/red] Significant vulnerabilities found. "
            "Address high-severity findings before production use."
        )
    if worst_grade == SecurityGrade.C:
        return (
            "[yellow]Moderate risk:[/yellow] Medium-severity issues present. "
            "Review and remediate before production deployment."
        )
    if worst_grade == SecurityGrade.B:
        return (
            "[green]Low risk:[/green] Minor issues found. "
            "Consider addressing low-severity findings."
        )
    return "[bold green]Secure:[/bold green] No significant issues detected. Servers meet security baseline."


def print_scan_results(results: list[ScanResult]) -> None:
    console.print()
    console.print(Rule("[bold cyan]MCP Shield Security Scan[/bold cyan]", style="cyan"))
    console.print()

    for result in results:
        console.print(_grade_panel(result))
        console.print()

        has_findings = bool(result.findings)
        if not has_findings:
            console.print(
                Panel(
                    "[bold green]No security issues found.[/bold green]",
                    border_style="green",
                    expand=False,
                )
            )
            console.print()
            continue

        for severity in _SEVERITY_ORDER:
            table = _findings_table(result.findings, severity)
            if table is None:
                continue
            style = _SEVERITY_STYLE[severity]
            console.print(
                Rule(
                    f"[{style}]{severity.value.upper()} ({sum(1 for f in result.findings if f.severity == severity)})[/{style}]",
                    style=style,
                )
            )
            console.print(table)
            console.print()

    console.print(Rule("[bold white]Summary[/bold white]", style="white"))
    console.print()
    console.print(_summary_table(results))
    console.print()
    console.print(Panel(_overall_recommendation(results), title="Recommendation", border_style="cyan"))
    console.print()
