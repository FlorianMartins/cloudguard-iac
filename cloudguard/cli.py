"""Command line interface.

Exit codes are the contract with CI systems:

===== ==========================================================
Code  Meaning
===== ==========================================================
``0`` scan completed, nothing at or above the failure threshold
``1`` at least one finding at or above the failure threshold
``2`` usage or runtime error (bad path, unreadable config…)
===== ==========================================================
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from cloudguard import __version__, engine, reporters
from cloudguard.config import ConfigError, find_config, load_config
from cloudguard.models import SEVERITY_ORDER, ScanResult, Severity
from cloudguard.reporters import console_reporter
from cloudguard.rules import DOCKER, TERRAFORM, Rule, all_rules
from cloudguard.scanners import DockerScanner, IaCScanner
from cloudguard.scanners.base import BaseScanner

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

_EPILOG = (
    "Exit codes: [bold]0[/bold] clean · [bold]1[/bold] findings at or above "
    "--fail-on · [bold]2[/bold] error.  "
    "Docs: https://github.com/FlorianMartins/cloudguard-iac"
)

app = typer.Typer(
    name="cloudguard",
    help=(
        "🛡️  [bold]CloudGuard-IaC[/bold] — shift-left security scanner for "
        "Terraform and container images."
    ),
    epilog=_EPILOG,
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)

#: Width used when the output is not a terminal (CI logs, redirections).
_PIPE_WIDTH = 120

err_console = Console(stderr=True)


def _make_console(no_color: bool = False, *, stderr: bool = False) -> Console:
    """Build a console that behaves well both in a terminal and in a CI log."""
    if no_color:
        return Console(
            stderr=stderr, no_color=True, force_terminal=False, highlight=False, width=_PIPE_WIDTH
        )
    console = Console(stderr=stderr, highlight=False)
    if not console.is_terminal:
        return Console(stderr=stderr, highlight=False, width=_PIPE_WIDTH)
    return console


class OutputFormat(str, Enum):
    """Supported report formats."""

    text = "text"
    json = "json"
    markdown = "markdown"
    html = "html"
    sarif = "sarif"


class FailOn(str, Enum):
    """Severity threshold that makes the command exit with code 1."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    never = "never"

    def to_severity(self) -> Severity | None:
        """``None`` for ``never`` — meaning "report but never fail"."""
        if self is FailOn.never:
            return None
        return Severity.parse(self.value)


class RulesFormat(str, Enum):
    """Output formats of the ``rules`` command."""

    table = "table"
    markdown = "markdown"
    json = "json"


# ---------------------------------------------------------------------------
# Reusable option types
# ---------------------------------------------------------------------------

PathsArg = Annotated[
    list[Path] | None,
    typer.Argument(
        metavar="PATHS...",
        help="Files or directories to scan. Defaults to the current directory.",
        show_default=False,
    ),
]
FailOnOpt = Annotated[
    FailOn | None,
    typer.Option(
        "--fail-on",
        "-f",
        help="Fail the command when a finding reaches this severity.  [default: high]",
        show_default=False,
    ),
]
FormatOpt = Annotated[
    OutputFormat,
    typer.Option("--format", "-F", help="Report format.", case_sensitive=False),
]
OutputOpt = Annotated[
    Path | None,
    typer.Option("--output", "-o", help="Write the report to a file instead of stdout."),
]
IgnoreOpt = Annotated[
    list[str] | None,
    typer.Option("--ignore", "-i", metavar="RULE_ID", help="Rule id to ignore (repeatable)."),
]
ExcludeOpt = Annotated[
    list[str] | None,
    typer.Option("--exclude", "-e", metavar="PATTERN", help="Path pattern to skip (repeatable)."),
]
DetailsOpt = Annotated[
    bool,
    typer.Option(
        "--details/--no-details", "-d", help="Print impact and remediation for each finding."
    ),
]
QuietOpt = Annotated[
    bool, typer.Option("--quiet", "-q", help="Print nothing but errors; rely on the exit code.")
]
NoColorOpt = Annotated[bool, typer.Option("--no-color", help="Disable coloured output.")]
ConfigOpt = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="Path to .cloudguard.toml (auto-discovered by default)."),
]
NoConfigOpt = Annotated[bool, typer.Option("--no-config", help="Ignore any .cloudguard.toml file.")]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cloudguard {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show the version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """CloudGuard-IaC command line entry point."""


# ---------------------------------------------------------------------------
# Shared scan implementation
# ---------------------------------------------------------------------------


def _resolve_paths(paths: Sequence[Path] | None) -> list[Path]:
    return list(paths) if paths else [Path()]


def _run_scan(
    scanners: list[BaseScanner],
    paths: Sequence[Path] | None,
    *,
    fail_on: FailOn | None,
    fmt: OutputFormat,
    output: Path | None,
    ignore: Sequence[str] | None,
    exclude: Sequence[str] | None,
    details: bool,
    quiet: bool,
    no_color: bool,
    config_path: Path | None,
    no_config: bool,
) -> None:
    """Run the scanners, emit the report and exit with the right code."""
    targets = _resolve_paths(paths)

    try:
        config_file = None if no_config else (config_path or find_config(targets[0]))
        config = load_config(config_file)
    except ConfigError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    # Precedence: the CLI flag wins, then the configuration file, then HIGH.
    if fail_on is not None:
        threshold = fail_on.to_severity()
    elif config.configures_threshold:
        threshold = config.fail_on
    else:
        threshold = Severity.HIGH
    ignored = [*(ignore or []), *config.ignore]
    excluded = [*(exclude or []), *config.exclude]

    try:
        result = engine.scan_paths(targets, scanners=scanners, ignore=ignored, exclude=excluded)
    except engine.ScanTargetError as exc:
        err_console.print(f"[bold red]error:[/bold red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    _emit(
        result,
        fmt=fmt,
        output=output,
        threshold=threshold,
        details=details,
        quiet=quiet,
        no_color=no_color,
        config_file=config.source,
    )

    if not result.files_scanned and not quiet:
        err_console.print(
            "[yellow]warning:[/yellow] no matching file found — "
            "check the path or the scanner you selected."
        )

    if threshold is not None and result.count_at_or_above(threshold):
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_OK)


def _emit(
    result: ScanResult,
    *,
    fmt: OutputFormat,
    output: Path | None,
    threshold: Severity | None,
    details: bool,
    quiet: bool,
    no_color: bool,
    config_file: Path | None = None,
) -> None:
    """Write the report where the user asked for it."""
    console = _make_console(no_color)

    if output is not None:
        content = reporters.render(result, fmt.value, threshold=threshold)
        destination = _write_report(content, output, fmt)
        if not quiet:
            console_reporter.render(result, console, threshold=threshold, details=details)
            console.print(f"[dim]report written to[/dim] {destination}")
            if config_file:
                console.print(f"[dim]configuration loaded from[/dim] {config_file}")
        return

    if quiet:
        return

    if fmt is OutputFormat.text:
        console_reporter.render(result, console, threshold=threshold, details=details)
        if config_file:
            console.print(f"[dim]configuration loaded from[/dim] {config_file}")
        return

    # Machine-readable format on stdout: emit the document and nothing else so
    # that `cloudguard full-scan -F json . | jq` works.
    typer.echo(reporters.render(result, fmt.value, threshold=threshold))


def _write_report(content: str, output: Path, fmt: OutputFormat) -> Path:
    """Write a report to disk, turning filesystem errors into a clean exit code 2."""
    destination = _with_extension(output, fmt)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[bold red]error:[/bold red] cannot write {destination}: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    return destination


def _with_extension(output: Path, fmt: OutputFormat) -> Path:
    """Append the format's default extension when the path has none."""
    if output.suffix:
        return output
    return output.with_suffix(reporters.EXTENSIONS[fmt.value])


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command("scan-iac", epilog=_EPILOG)
def scan_iac(
    paths: PathsArg = None,
    fail_on: FailOnOpt = None,
    fmt: FormatOpt = OutputFormat.text,
    output: OutputOpt = None,
    ignore: IgnoreOpt = None,
    exclude: ExcludeOpt = None,
    details: DetailsOpt = False,
    quiet: QuietOpt = False,
    no_color: NoColorOpt = False,
    config: ConfigOpt = None,
    no_config: NoConfigOpt = False,
) -> None:
    """Scan [bold]Terraform[/bold] files (``.tf``, ``.tfvars``) for misconfigurations.

    [bold]Examples[/bold]

      cloudguard scan-iac infrastructure/

      cloudguard scan-iac . --fail-on critical --details

      cloudguard scan-iac examples/vulnerable -F html -o reports/iac
    """
    _run_scan(
        [IaCScanner()],
        paths,
        fail_on=fail_on,
        fmt=fmt,
        output=output,
        ignore=ignore,
        exclude=exclude,
        details=details,
        quiet=quiet,
        no_color=no_color,
        config_path=config,
        no_config=no_config,
    )


@app.command("scan-docker", epilog=_EPILOG)
def scan_docker(
    paths: PathsArg = None,
    fail_on: FailOnOpt = None,
    fmt: FormatOpt = OutputFormat.text,
    output: OutputOpt = None,
    ignore: IgnoreOpt = None,
    exclude: ExcludeOpt = None,
    details: DetailsOpt = False,
    quiet: QuietOpt = False,
    no_color: NoColorOpt = False,
    config: ConfigOpt = None,
    no_config: NoConfigOpt = False,
) -> None:
    """Scan [bold]Dockerfiles[/bold] for insecure build and runtime practices.

    [bold]Examples[/bold]

      cloudguard scan-docker Dockerfile

      cloudguard scan-docker services/ --fail-on medium
    """
    _run_scan(
        [DockerScanner()],
        paths,
        fail_on=fail_on,
        fmt=fmt,
        output=output,
        ignore=ignore,
        exclude=exclude,
        details=details,
        quiet=quiet,
        no_color=no_color,
        config_path=config,
        no_config=no_config,
    )


@app.command("full-scan", epilog=_EPILOG)
def full_scan(
    paths: PathsArg = None,
    fail_on: FailOnOpt = None,
    fmt: FormatOpt = OutputFormat.text,
    output: OutputOpt = None,
    ignore: IgnoreOpt = None,
    exclude: ExcludeOpt = None,
    details: DetailsOpt = False,
    quiet: QuietOpt = False,
    no_color: NoColorOpt = False,
    config: ConfigOpt = None,
    no_config: NoConfigOpt = False,
) -> None:
    """Run [bold]every scanner[/bold] (Terraform + Docker) over the given paths.

    [bold]Examples[/bold]

      cloudguard full-scan .

      cloudguard full-scan . -F json -o build/results.json

      cloudguard full-scan . --ignore CG_IAC_015 --exclude 'examples/**'
    """
    _run_scan(
        [IaCScanner(), DockerScanner()],
        paths,
        fail_on=fail_on,
        fmt=fmt,
        output=output,
        ignore=ignore,
        exclude=exclude,
        details=details,
        quiet=quiet,
        no_color=no_color,
        config_path=config,
        no_config=no_config,
    )


@app.command("generate-report", epilog=_EPILOG)
def generate_report(
    input_file: Annotated[
        Path,
        typer.Option(
            "--input",
            "-I",
            help="JSON result file produced by a scan run with `-F json`.",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    fmt: Annotated[
        OutputFormat,
        typer.Option("--format", "-F", help="Report format to generate.", case_sensitive=False),
    ] = OutputFormat.html,
    output: OutputOpt = None,
    fail_on: FailOnOpt = None,
    quiet: QuietOpt = False,
    no_color: NoColorOpt = False,
) -> None:
    """Render a stored JSON result as [bold]HTML[/bold], Markdown, SARIF or text.

    Scan once, publish everywhere — the CI pipeline scans a single time and turns
    the same JSON into the artefacts each audience needs.

    [bold]Examples[/bold]

      cloudguard full-scan . -F json -o results.json

      cloudguard generate-report -I results.json -F html -o report.html

      cloudguard generate-report -I results.json -F markdown >> $GITHUB_STEP_SUMMARY
    """
    try:
        payload = json.loads(input_file.read_text(encoding="utf-8"))
        result = ScanResult.from_dict(payload)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        err_console.print(f"[bold red]error:[/bold red] cannot read {input_file}: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    threshold = fail_on.to_severity() if fail_on is not None else Severity.HIGH

    if output is None and fmt is OutputFormat.text and not quiet:
        console_reporter.render(result, _make_console(no_color), threshold=threshold)
    elif output is None:
        typer.echo(reporters.render(result, fmt.value, threshold=threshold))
    else:
        destination = _write_report(
            reporters.render(result, fmt.value, threshold=threshold), output, fmt
        )
        if not quiet:
            _make_console(no_color).print(
                f"[green]✔[/green] {fmt.value} report written to [bold]{destination}[/bold] "
                f"({len(result.findings)} finding(s))"
            )

    if threshold is not None and result.count_at_or_above(threshold):
        raise typer.Exit(EXIT_FINDINGS)
    raise typer.Exit(EXIT_OK)


@app.command("rules", epilog=_EPILOG)
def list_rules(
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            "-C",
            help=f"Filter by category: {TERRAFORM} or {DOCKER}.",
        ),
    ] = None,
    severity: Annotated[
        FailOn | None,
        typer.Option("--severity", "-s", help="Only rules at or above this severity."),
    ] = None,
    fmt: Annotated[
        RulesFormat,
        typer.Option("--format", "-F", help="Output format.", case_sensitive=False),
    ] = RulesFormat.table,
    no_color: NoColorOpt = False,
) -> None:
    """List the [bold]detection rules[/bold] shipped with CloudGuard.

    The Markdown output is the exact table published in the README, so the
    documentation can never drift from the implementation:

      cloudguard rules -F markdown > docs/rules.md
    """
    if category is not None and category not in (TERRAFORM, DOCKER):
        err_console.print(
            f"[bold red]error:[/bold red] unknown category {category!r} "
            f"(expected {TERRAFORM} or {DOCKER})"
        )
        raise typer.Exit(EXIT_ERROR)

    minimum = severity.to_severity() if severity is not None else None
    rules = all_rules(category=category, min_severity=minimum)

    if fmt is RulesFormat.json:
        typer.echo(json.dumps([rule.to_dict() for rule in rules], indent=2, ensure_ascii=False))
        raise typer.Exit(EXIT_OK)

    if fmt is RulesFormat.markdown:
        typer.echo(_rules_markdown(rules))
        raise typer.Exit(EXIT_OK)

    console = _make_console(no_color)
    table = Table(
        title=f"CloudGuard-IaC — {len(rules)} detection rules",
        header_style="bold",
        title_style="bold",
        show_lines=False,
    )
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("SEVERITY", no_wrap=True)
    table.add_column("CATEGORY", style="magenta", no_wrap=True)
    table.add_column("TITLE")
    for rule in rules:
        table.add_row(
            rule.id,
            Text(rule.severity.value, style=f"bold {rule.severity.color}"),
            rule.category,
            rule.title,
        )
    console.print(table)

    counts = {sev: sum(1 for r in rules if r.severity is sev) for sev in SEVERITY_ORDER}
    console.print(
        "  ".join(
            f"[bold {sev.color}]{counts[sev]}[/bold {sev.color}] "
            f"[{sev.color}]{sev.value.lower()}[/{sev.color}]"
            for sev in SEVERITY_ORDER
            if counts[sev]
        )
    )
    raise typer.Exit(EXIT_OK)


def _rules_markdown(rules: Sequence[Rule]) -> str:
    """Render the rules as the Markdown table published in the README."""
    lines = [
        "| Rule | Severity | Target | What it detects | Why it is dangerous | Remediation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for rule in rules:
        why = rule.why.replace("|", "\\|").replace("\n", " ")
        fix = rule.remediation.replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{rule.id}` "
            f"| **{rule.severity.value}** "
            f"| {rule.category} "
            f"| {rule.title} "
            f"| {why} "
            f"| {fix} |"
        )
    return "\n".join(lines)


def run() -> None:  # pragma: no cover - thin wrapper used by the console script
    """Entry point declared in ``pyproject.toml``."""
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
