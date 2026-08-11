"""Console reporter — the developer-facing output, powered by Rich."""

from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cloudguard.engine import group_by_file
from cloudguard.models import SEVERITY_ORDER, ScanResult, Severity


def _summary_line(result: ScanResult) -> Text:
    """One coloured line with the count of findings per severity."""
    counts = result.counts()
    text = Text()
    first = True
    for severity in SEVERITY_ORDER:
        count = counts[severity]
        if not count:
            continue
        if not first:
            text.append("   ")
        first = False
        text.append(f"{count}", style=f"bold {severity.color}")
        text.append(f" {severity.value.lower()}", style=severity.color)
    if first:
        text.append("no findings", style="bold green")
    return text


def render(
    result: ScanResult,
    console: Console,
    *,
    threshold: Severity | None = None,
    details: bool = False,
) -> None:
    """Print a scan result to ``console``."""
    console.print()
    console.print(
        Text.assemble(
            ("🛡️  CloudGuard-IaC", "bold"),
            (f"  v{result.tool_version}", "dim"),
            ("  ·  ", "dim"),
            (f"{len(result.files_scanned)} file(s)", "dim"),
            ("  ·  ", "dim"),
            (f"{result.duration_seconds:.2f}s", "dim"),
        )
    )

    if result.errors:
        for error in result.errors:
            console.print(Text.assemble(("  ! ", "yellow"), (error, "yellow")))

    if result.findings:
        for path, findings in group_by_file(result.findings).items():
            console.print()
            console.print(Text(path, style="bold underline"))
            table = Table(
                show_header=True,
                header_style="dim",
                box=None,
                pad_edge=False,
                padding=(0, 1),
                expand=False,
            )
            table.add_column("LINE", justify="right", style="dim", no_wrap=True)
            table.add_column("SEVERITY", no_wrap=True)
            table.add_column("RULE", style="cyan", no_wrap=True)
            table.add_column("RESOURCE", style="magenta", no_wrap=True, max_width=34)
            table.add_column("ISSUE", overflow="fold")

            for finding in findings:
                table.add_row(
                    str(finding.line),
                    Text(finding.severity.value, style=f"bold {finding.severity.color}"),
                    finding.rule_id,
                    finding.resource,
                    finding.message,
                )
            console.print(table)

            if details:
                for finding in findings:
                    console.print()
                    console.print(
                        Text.assemble(
                            ("  ", ""),
                            (f"{finding.rule_id} ", f"bold {finding.severity.color}"),
                            (finding.title, "bold"),
                            (f"  ({finding.location})", "dim"),
                        )
                    )
                    if finding.why:
                        console.print(Text(f"    why  {finding.why}", style="dim"))
                    if finding.remediation:
                        console.print(Text(f"    fix  {finding.remediation}", style="green"))

    console.print()
    console.print(Text.assemble(("Summary  ", "bold"), _summary_line(result)))
    if result.suppressed:
        console.print(
            Text(
                f"         {result.suppressed} finding(s) suppressed by inline directives",
                style="dim",
            )
        )

    if threshold is None:
        return

    blocking = result.count_at_or_above(threshold)
    if blocking:
        console.print()
        console.print(
            Panel(
                Text.assemble(
                    (f"{blocking} finding(s) at or above {threshold.value}. ", "bold"),
                    ("This scan fails the build (exit code 1).", ""),
                ),
                title="❌ FAILED",
                border_style="red",
                expand=False,
            )
        )
    else:
        console.print()
        message = (
            "No finding at or above the failure threshold."
            if result.findings
            else "No security issue detected."
        )
        console.print(
            Panel(
                Text.assemble((message + " ", "bold"), ("Exit code 0.", "")),
                title="✅ PASSED",
                border_style="green",
                expand=False,
            )
        )


def render_text(
    result: ScanResult,
    *,
    threshold: Severity | None = None,
    details: bool = False,
    width: int = 120,
) -> str:
    """Render the console report to a plain string (used by ``--output``)."""
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=False, no_color=True, width=width)
    render(result, console, threshold=threshold, details=details)
    return buffer.getvalue()
