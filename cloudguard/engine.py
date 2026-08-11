"""Scan orchestration: file discovery, scanner dispatch, result assembly."""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from pathlib import Path

from cloudguard import __version__
from cloudguard.models import Finding, ScanResult
from cloudguard.scanners.base import DEFAULT_EXCLUDES, BaseScanner, apply_suppressions
from cloudguard.scanners.docker_scanner import DockerScanner
from cloudguard.scanners.iac_scanner import IaCScanner

#: Scanner classes enabled by ``full-scan``.
ALL_SCANNERS: tuple[type[BaseScanner], ...] = (IaCScanner, DockerScanner)


class ScanTargetError(ValueError):
    """Raised when a requested path does not exist."""


def _display_path(path: Path, root: Path) -> str:
    """Path shown in reports: relative to the working directory when possible."""
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def _excluded(path: Path, patterns: Sequence[str], root: Path) -> bool:
    """``True`` when a path matches one of the user-supplied exclude patterns."""
    if not patterns:
        return False
    shown = _display_path(path, root)
    for pattern in patterns:
        cleaned = pattern.rstrip("/")
        if not cleaned:
            continue
        if Path(shown).match(cleaned) or shown == cleaned:
            return True
        if shown.startswith(f"{cleaned}/"):
            return True
    return False


def scan_paths(
    paths: Iterable[str | Path],
    *,
    scanners: Sequence[BaseScanner] | None = None,
    ignore: Iterable[str] = (),
    exclude: Sequence[str] = (),
    root: Path | None = None,
) -> ScanResult:
    """Scan files and directories and return the aggregated result.

    Args:
        paths: Files or directories to analyse.
        scanners: Scanner instances to run; defaults to every scanner.
        ignore: Rule ids to drop from the results.
        exclude: Glob-ish path patterns to skip.
        root: Base directory used to compute the displayed relative paths.

    Raises:
        ScanTargetError: when one of the paths does not exist.
    """
    started = time.perf_counter()
    base = (root or Path.cwd()).resolve()
    targets = [Path(p) for p in paths]
    for target in targets:
        if not target.exists():
            raise ScanTargetError(f"path not found: {target}")

    active: list[BaseScanner] = (
        list(scanners) if scanners is not None else [cls() for cls in ALL_SCANNERS]
    )
    ignored = {rule.strip().upper() for rule in ignore if rule.strip()}

    result = ScanResult(tool_version=__version__, target=", ".join(str(t) for t in targets))
    scanned: set[str] = set()

    for scanner in active:
        sources: dict[str, str] = {}
        for target in targets:
            for path in scanner.discover(target, DEFAULT_EXCLUDES):
                if _excluded(path, exclude, base):
                    continue
                shown = _display_path(path, base)
                if shown in sources:
                    continue
                try:
                    sources[shown] = path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    result.errors.append(f"{shown}: cannot read file ({exc})")

        if not sources:
            continue

        findings = scanner.analyse_files(sources)
        kept, suppressed = apply_suppressions(findings, sources)
        result.suppressed += suppressed
        result.extend([f for f in kept if f.rule_id not in ignored])
        result.errors.extend(getattr(scanner, "errors", []))
        scanned.update(sources)

    result.files_scanned = sorted(scanned)
    result.duration_seconds = time.perf_counter() - started
    return result


def scan_iac(paths: Iterable[str | Path], **kwargs: object) -> ScanResult:
    """Scan Terraform files only."""
    return scan_paths(paths, scanners=[IaCScanner()], **kwargs)  # type: ignore[arg-type]


def scan_docker(paths: Iterable[str | Path], **kwargs: object) -> ScanResult:
    """Scan Dockerfiles only."""
    return scan_paths(paths, scanners=[DockerScanner()], **kwargs)  # type: ignore[arg-type]


def group_by_file(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    """Group findings by file, keeping the severity ordering inside each group."""
    grouped: dict[str, list[Finding]] = {}
    for finding in sorted(findings, key=lambda f: f.sort_key()):
        grouped.setdefault(finding.file, []).append(finding)
    return grouped
