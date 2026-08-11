"""Core data model shared by scanners, reporters and the CLI."""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity of a finding, ordered from the most to the least critical."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Numeric weight: higher means more severe (used for comparisons)."""
        return _SEVERITY_WEIGHTS[self]

    @property
    def color(self) -> str:
        """Rich markup colour used by the console reporter."""
        return _SEVERITY_COLORS[self]

    @property
    def hex_color(self) -> str:
        """Hexadecimal colour used by the HTML reporter."""
        return _SEVERITY_HEX[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a severity from a case-insensitive string."""
        try:
            return cls(value.strip().upper())
        except ValueError as exc:  # pragma: no cover - defensive
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {valid})") from exc

    def __lt__(self, other: object) -> bool:
        """``True`` when this severity is less severe than ``other``."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight < other.weight

    def __le__(self, other: object) -> bool:
        """``True`` when this severity is at most as severe as ``other``."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight <= other.weight

    def __gt__(self, other: object) -> bool:
        """``True`` when this severity is more severe than ``other``."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight > other.weight

    def __ge__(self, other: object) -> bool:
        """``True`` when this severity is at least as severe as ``other``."""
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight >= other.weight


_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "blue",
}

_SEVERITY_HEX: dict[Severity, str] = {
    Severity.CRITICAL: "#b3261e",
    Severity.HIGH: "#d1642a",
    Severity.MEDIUM: "#b8860b",
    Severity.LOW: "#2a6f97",
    Severity.INFO: "#5a6472",
}

#: Severities from the most to the least critical — handy for ordered reports.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


@dataclass(frozen=True)
class Finding:
    """A single security issue detected in a file.

    Attributes:
        rule_id: Stable identifier of the rule that fired (``CG_IAC_001``…).
        title: Short human readable title of the rule.
        severity: Severity of *this* occurrence (a rule may downgrade or
            upgrade its default severity depending on the context).
        file: Path of the analysed file, relative to the scan root when possible.
        line: 1-indexed line number the finding is anchored to.
        resource: Identifier of the offending object
            (``aws_s3_bucket.data``, ``Dockerfile:stage runtime``…).
        message: What was found, in one sentence.
        remediation: How to fix it, in one actionable sentence.
        why: Why it is dangerous (impact-oriented explanation).
        references: External references (CIS benchmark, CWE, vendor docs).
        snippet: The offending source line, trimmed.
        category: ``terraform`` or ``docker``.
    """

    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int
    resource: str
    message: str
    remediation: str = ""
    why: str = ""
    references: tuple[str, ...] = ()
    snippet: str = ""
    category: str = ""

    @property
    def location(self) -> str:
        """``path:line`` location, clickable in most terminals and editors."""
        return f"{self.file}:{self.line}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise the finding to a JSON-compatible dictionary."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "resource": self.resource,
            "message": self.message,
            "remediation": self.remediation,
            "why": self.why,
            "references": list(self.references),
            "snippet": self.snippet,
            "category": self.category,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Rebuild a finding from :meth:`to_dict` output."""
        return cls(
            rule_id=str(data["rule_id"]),
            title=str(data.get("title", "")),
            severity=Severity.parse(str(data["severity"])),
            file=str(data.get("file", "")),
            line=int(data.get("line", 0)),
            resource=str(data.get("resource", "")),
            message=str(data.get("message", "")),
            remediation=str(data.get("remediation", "")),
            why=str(data.get("why", "")),
            references=tuple(data.get("references", ())),
            snippet=str(data.get("snippet", "")),
            category=str(data.get("category", "")),
        )

    def sort_key(self) -> tuple[int, str, int, str]:
        """Sort by descending severity, then by file, line and rule id."""
        return (-self.severity.weight, self.file, self.line, self.rule_id)


@dataclass
class ScanResult:
    """Aggregated outcome of a scan."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    suppressed: int = 0
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    tool_version: str = ""
    scanned_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )
    target: str = ""

    def add(self, finding: Finding) -> None:
        """Append a finding."""
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        """Append several findings."""
        self.findings.extend(findings)

    def merge(self, other: ScanResult) -> ScanResult:
        """Merge another result into this one and return ``self``."""
        self.findings.extend(other.findings)
        self.files_scanned.extend(other.files_scanned)
        self.suppressed += other.suppressed
        self.errors.extend(other.errors)
        self.duration_seconds += other.duration_seconds
        return self

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered by descending severity then location."""
        return sorted(self.findings, key=lambda f: f.sort_key())

    def counts(self) -> dict[Severity, int]:
        """Number of findings per severity (always contains every severity)."""
        counts = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def count_at_or_above(self, threshold: Severity) -> int:
        """Number of findings whose severity is >= ``threshold``."""
        return sum(1 for f in self.findings if f.severity >= threshold)

    @property
    def max_severity(self) -> Severity | None:
        """Highest severity found, or ``None`` when the scan is clean."""
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.weight)

    @property
    def is_clean(self) -> bool:
        """``True`` when no finding was reported."""
        return not self.findings

    def to_dict(self) -> dict[str, Any]:
        """Serialise the whole result to a JSON-compatible dictionary."""
        counts = self.counts()
        return {
            "schema": "cloudguard.scan-result/v1",
            "tool": "cloudguard-iac",
            "tool_version": self.tool_version,
            "scanned_at": self.scanned_at,
            "target": self.target,
            "duration_seconds": round(self.duration_seconds, 4),
            "summary": {
                "total": len(self.findings),
                "files_scanned": len(self.files_scanned),
                "suppressed": self.suppressed,
                "by_severity": {sev.value: counts[sev] for sev in SEVERITY_ORDER},
                "max_severity": self.max_severity.value if self.max_severity else None,
            },
            "files_scanned": list(self.files_scanned),
            "errors": list(self.errors),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanResult:
        """Rebuild a result from :meth:`to_dict` output (used by ``generate-report``)."""
        summary = data.get("summary", {})
        return cls(
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            files_scanned=list(data.get("files_scanned", [])),
            suppressed=int(summary.get("suppressed", 0)),
            errors=list(data.get("errors", [])),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            tool_version=str(data.get("tool_version", "")),
            scanned_at=str(data.get("scanned_at", "")),
            target=str(data.get("target", "")),
        )
