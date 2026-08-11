"""HTML reporter — a single self-contained dashboard file.

The output embeds its own CSS and JavaScript: no CDN, no external font, no
network call. That matters because these reports are published as CI artefacts
and opened from a browser that may have no Internet access, and because a
security tool should not phone home.
"""

from __future__ import annotations

from html import escape

from cloudguard.engine import group_by_file
from cloudguard.models import SEVERITY_ORDER, Finding, ScanResult, Severity

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f4f6f8;
  --surface: #ffffff;
  --surface-alt: #f8fafc;
  --border: #dfe3e8;
  --text: #1b2027;
  --muted: #5f6b7a;
  --accent: #1f6feb;
  --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 4px 12px rgba(16, 24, 40, .06);
  --critical: #b3261e; --high: #d1642a; --medium: #b8860b; --low: #2a6f97; --info: #5a6472;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --surface: #161b22; --surface-alt: #11161d; --border: #2a313c;
    --text: #e6edf3; --muted: #9aa7b4; --accent: #58a6ff;
    --shadow: none;
    --critical: #f85149; --high: #ff9f4a; --medium: #e3b341; --low: #79c0ff; --info: #8b949e;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem;
  background: var(--bg); color: var(--text);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1080px; margin: 0 auto; }
header { margin-bottom: 1.75rem; }
h1 { font-size: 1.6rem; margin: 0 0 .35rem; letter-spacing: -.01em; }
h1 .shield { margin-right: .4rem; }
.meta { color: var(--muted); font-size: .875rem; margin: 0; }
.meta code { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: .05rem .3rem; }
.verdict {
  margin: 1.25rem 0; padding: .85rem 1.1rem; border-radius: 10px;
  border: 1px solid var(--border); background: var(--surface); box-shadow: var(--shadow);
  font-weight: 600; display: flex; align-items: center; gap: .6rem;
}
.verdict.fail { border-left: 4px solid var(--critical); }
.verdict.pass { border-left: 4px solid #2da44e; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: .75rem; margin-bottom: 1.5rem; }
.card {
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: .85rem 1rem; cursor: pointer; text-align: left; box-shadow: var(--shadow);
  transition: transform .12s ease, border-color .12s ease; font: inherit; color: inherit;
}
.card:hover { transform: translateY(-1px); }
.card[aria-pressed="true"] { border-color: var(--accent); box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent); }
.card .count { font-size: 1.75rem; font-weight: 700; line-height: 1.1; }
.card .label { font-size: .72rem; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.card.critical .count { color: var(--critical); } .card.high .count { color: var(--high); }
.card.medium .count { color: var(--medium); } .card.low .count { color: var(--low); }
.card.info .count { color: var(--info); } .card.total .count { color: var(--text); }
.toolbar { display: flex; gap: .6rem; align-items: center; margin-bottom: 1rem; flex-wrap: wrap; }
input[type="search"] {
  flex: 1 1 260px; padding: .55rem .75rem; border-radius: 8px; font: inherit;
  border: 1px solid var(--border); background: var(--surface); color: var(--text);
}
.hint { color: var(--muted); font-size: .82rem; }
.file { margin-bottom: 1.5rem; }
.file > h2 {
  font-size: .95rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  margin: 0 0 .6rem; color: var(--muted); font-weight: 600;
}
.file > h2 .n { font-family: inherit; background: var(--surface); border: 1px solid var(--border);
  border-radius: 999px; padding: 0 .5rem; font-size: .75rem; margin-left: .4rem; }
details.finding {
  background: var(--surface); border: 1px solid var(--border); border-left-width: 4px;
  border-radius: 8px; margin-bottom: .5rem; box-shadow: var(--shadow); overflow: hidden;
}
details.finding.critical { border-left-color: var(--critical); }
details.finding.high { border-left-color: var(--high); }
details.finding.medium { border-left-color: var(--medium); }
details.finding.low { border-left-color: var(--low); }
details.finding.info { border-left-color: var(--info); }
summary { padding: .7rem .9rem; cursor: pointer; display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
summary::-webkit-details-marker { display: none; }
.chip {
  font-size: .68rem; font-weight: 700; letter-spacing: .06em; padding: .12rem .45rem;
  border-radius: 4px; color: #fff; flex: none;
}
.chip.critical { background: var(--critical); } .chip.high { background: var(--high); }
.chip.medium { background: var(--medium); } .chip.low { background: var(--low); }
.chip.info { background: var(--info); }
.rule { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .78rem; color: var(--muted); }
.title { font-weight: 600; }
.loc { margin-left: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .78rem; color: var(--muted); }
.body { padding: 0 .9rem .9rem; border-top: 1px solid var(--border); }
.body dl { display: grid; grid-template-columns: max-content 1fr; gap: .35rem .9rem; margin: .9rem 0 0; }
.body dt { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .06em; }
.body dd { margin: 0; }
pre.snippet {
  background: var(--surface-alt); border: 1px solid var(--border); border-radius: 6px;
  padding: .6rem .75rem; overflow-x: auto; margin: .9rem 0 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem;
}
.body ul { margin: .3rem 0 0; padding-left: 1.1rem; }
.body a { color: var(--accent); word-break: break-all; }
.empty { background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
  padding: 2.5rem 1rem; text-align: center; box-shadow: var(--shadow); }
.empty .big { font-size: 2.5rem; }
footer { margin-top: 2.5rem; color: var(--muted); font-size: .8rem; text-align: center; }
footer a { color: var(--accent); }
.errors { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--medium);
  border-radius: 8px; padding: .75rem .9rem; margin-bottom: 1.5rem; font-size: .85rem; }
"""

_JS = """
(function () {
  var active = null;
  var search = document.getElementById('search');
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card[data-severity]'));

  function apply() {
    var term = (search.value || '').toLowerCase();
    document.querySelectorAll('details.finding').forEach(function (node) {
      var matchesSeverity = !active || node.dataset.severity === active;
      var matchesTerm = !term || node.dataset.haystack.indexOf(term) !== -1;
      node.hidden = !(matchesSeverity && matchesTerm);
    });
    document.querySelectorAll('.file').forEach(function (group) {
      var visible = group.querySelectorAll('details.finding:not([hidden])').length;
      group.hidden = visible === 0;
    });
    var none = document.getElementById('no-match');
    if (none) {
      none.hidden = document.querySelectorAll('details.finding:not([hidden])').length > 0;
    }
  }

  cards.forEach(function (card) {
    card.addEventListener('click', function () {
      active = active === card.dataset.severity ? null : card.dataset.severity;
      cards.forEach(function (other) {
        other.setAttribute('aria-pressed', String(other.dataset.severity === active));
      });
      apply();
    });
  });
  if (search) { search.addEventListener('input', apply); }
})();
"""


def _chip(severity: Severity) -> str:
    return severity.value.lower()


def _finding_html(finding: Finding) -> str:
    css_class = _chip(finding.severity)
    haystack = escape(
        " ".join(
            [
                finding.rule_id,
                finding.title,
                finding.file,
                finding.resource,
                finding.message,
                finding.snippet,
            ]
        ).lower(),
        quote=True,
    )
    parts = [
        f'<details class="finding {css_class}" data-severity="{css_class}" '
        f'data-haystack="{haystack}">',
        "<summary>",
        f'<span class="chip {css_class}">{escape(finding.severity.value)}</span>',
        f'<span class="rule">{escape(finding.rule_id)}</span>',
        f'<span class="title">{escape(finding.title)}</span>',
        f'<span class="loc">{escape(finding.location)}</span>',
        "</summary>",
        '<div class="body">',
    ]
    if finding.snippet:
        parts.append(f'<pre class="snippet">{escape(finding.snippet)}</pre>')
    parts.append("<dl>")
    parts.append(f"<dt>Resource</dt><dd><code>{escape(finding.resource)}</code></dd>")
    parts.append(f"<dt>Issue</dt><dd>{escape(finding.message)}</dd>")
    if finding.why:
        parts.append(f"<dt>Why</dt><dd>{escape(finding.why)}</dd>")
    if finding.remediation:
        parts.append(f"<dt>Fix</dt><dd>{escape(finding.remediation)}</dd>")
    if finding.references:
        links = "".join(
            f'<li><a href="{escape(ref, quote=True)}" rel="noreferrer noopener" '
            f'target="_blank">{escape(ref)}</a></li>'
            for ref in finding.references
        )
        parts.append(f"<dt>Refs</dt><dd><ul>{links}</ul></dd>")
    parts.append("</dl></div></details>")
    return "".join(parts)


def render(result: ScanResult, *, threshold: Severity | None = None) -> str:
    """Render a scan result as a standalone HTML page."""
    counts = result.counts()
    total = len(result.findings)
    blocking = result.count_at_or_above(threshold) if threshold else 0

    cards = [
        '<button class="card total" type="button" disabled>'
        f'<div class="count">{total}</div><div class="label">Total</div></button>'
    ]
    for severity in SEVERITY_ORDER:
        css_class = _chip(severity)
        cards.append(
            f'<button class="card {css_class}" type="button" data-severity="{css_class}" '
            f'aria-pressed="false" title="Filter on {severity.value}">'
            f'<div class="count">{counts[severity]}</div>'
            f'<div class="label">{escape(severity.value)}</div></button>'
        )

    if total == 0:
        verdict = '<div class="verdict pass">✅ No security issue detected.</div>'
    elif threshold is not None and blocking:
        verdict = (
            '<div class="verdict fail">❌ Build blocked — '
            f"{blocking} finding(s) at or above {escape(threshold.value)}.</div>"
        )
    else:
        verdict = (
            '<div class="verdict pass">⚠️ Advisory findings only — '
            "nothing at or above the failure threshold.</div>"
        )

    body: list[str] = []
    if total:
        body.append(
            '<div class="toolbar">'
            '<input type="search" id="search" placeholder="Filter by rule, file, resource…" '
            'aria-label="Filter findings">'
            '<span class="hint">Click a severity card to filter</span>'
            "</div>"
        )
        for path, findings in group_by_file(result.findings).items():
            cards_html = "".join(_finding_html(f) for f in findings)
            body.append(
                f'<section class="file"><h2>{escape(path)}'
                f'<span class="n">{len(findings)}</span></h2>{cards_html}</section>'
            )
        body.append(
            '<div class="empty" id="no-match" hidden>'
            '<div class="big">🔍</div><p>No finding matches the current filter.</p></div>'
        )
    else:
        body.append(
            '<div class="empty"><div class="big">🛡️</div>'
            "<p><strong>All clear.</strong> Every CloudGuard rule passed on "
            f"{len(result.files_scanned)} analysed file(s).</p></div>"
        )

    errors_html = ""
    if result.errors:
        items = "".join(f"<li><code>{escape(error)}</code></li>" for error in result.errors)
        errors_html = f'<div class="errors"><strong>Scan errors</strong><ul>{items}</ul></div>'

    suppressed = (
        f" — {result.suppressed} suppressed by inline directives" if result.suppressed else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="CloudGuard-IaC v{escape(result.tool_version)}">
<title>CloudGuard-IaC — security report</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1><span class="shield">🛡️</span>CloudGuard-IaC — security report</h1>
  <p class="meta">
    Target <code>{escape(result.target or ".")}</code> ·
    {len(result.files_scanned)} file(s) analysed ·
    {result.duration_seconds:.2f}s ·
    {escape(result.scanned_at)} ·
    v{escape(result.tool_version)}{escape(suppressed)}
  </p>
</header>
{verdict}
<div class="cards">{"".join(cards)}</div>
{errors_html}
{"".join(body)}
<footer>
  Generated by
  <a href="https://github.com/FlorianMartins/cloudguard-iac" rel="noreferrer noopener">CloudGuard-IaC</a>
  — shift-left security for Terraform and containers.
</footer>
</div>
<script>{_JS}</script>
</body>
</html>
"""
