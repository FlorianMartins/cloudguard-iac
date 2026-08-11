"""Report renderers.

Every renderer takes a :class:`~cloudguard.models.ScanResult` and returns a
string, so the CLI can write any format to stdout or to a file with the same
code path.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from cloudguard.models import ScanResult, Severity
from cloudguard.reporters import (
    console_reporter,
    html_reporter,
    markdown_reporter,
    sarif_reporter,
)


def _render_json(result: ScanResult, *, threshold: Severity | None = None) -> str:
    """Machine-readable output — the input of ``cloudguard generate-report``."""
    payload = result.to_dict()
    if threshold is not None:
        payload["summary"]["fail_on"] = threshold.value
        payload["summary"]["blocking"] = result.count_at_or_above(threshold)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _render_text(result: ScanResult, *, threshold: Severity | None = None) -> str:
    return console_reporter.render_text(result, threshold=threshold)


#: Renderers exposed through ``--format``.
RENDERERS: dict[str, Callable[..., str]] = {
    "text": _render_text,
    "json": _render_json,
    "markdown": markdown_reporter.render,
    "html": html_reporter.render,
    "sarif": sarif_reporter.render,
}

#: Default file extension per format, used when ``--output`` has none.
EXTENSIONS: dict[str, str] = {
    "text": ".txt",
    "json": ".json",
    "markdown": ".md",
    "html": ".html",
    "sarif": ".sarif",
}

FORMATS: tuple[str, ...] = tuple(RENDERERS)


def render(result: ScanResult, fmt: str, *, threshold: Severity | None = None) -> str:
    """Render ``result`` in the requested format.

    Raises:
        KeyError: for an unknown format (the CLI validates before calling).
    """
    return RENDERERS[fmt](result, threshold=threshold)


__all__ = [
    "EXTENSIONS",
    "FORMATS",
    "RENDERERS",
    "console_reporter",
    "html_reporter",
    "markdown_reporter",
    "render",
    "sarif_reporter",
]
