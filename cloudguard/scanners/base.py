"""Shared plumbing for scanners: file matching, suppressions, finding factory."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from cloudguard.models import Finding, Severity
from cloudguard.rules import get_rule

#: ``# cloudguard:ignore`` — optionally followed by a comma/space separated rule list.
_IGNORE_RE = re.compile(
    r"(?:#|//|/\*)\s*cloudguard:ignore(?P<file>-file)?(?P<rules>[^\n*]*)",
    re.IGNORECASE,
)

#: Directories never worth walking into.
DEFAULT_EXCLUDES: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".terraform",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "site-packages",
        "dist",
        "build",
        ".tox",
    }
)

#: Everything a rule matches on is lowercase; keep the tokens in one place.
SENSITIVE_NAME_TOKENS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "private_key",
    "credential",
    "auth_key",
    "client_secret",
)


@dataclass
class Suppressions:
    """Inline ``cloudguard:ignore`` directives found in a file."""

    whole_file: bool = False
    #: line number -> rule ids to ignore; an empty set means "every rule".
    by_line: dict[int, set[str]] = field(default_factory=dict)

    def allows(self, rule_id: str, line: int) -> bool:
        """``True`` when ``rule_id`` at ``line`` is suppressed by a directive.

        A directive applies to its own line and to the line right after it, so
        both of these work::

            acl = "public-read"  # cloudguard:ignore CG_IAC_001
            # cloudguard:ignore CG_IAC_001
            acl = "public-read"
        """
        if self.whole_file:
            return True
        for candidate in (line, line - 1):
            rules = self.by_line.get(candidate)
            if rules is None:
                continue
            if not rules or rule_id in rules:
                return True
        return False

    @classmethod
    def parse(cls, text: str) -> Suppressions:
        """Extract every ignore directive from a source file."""
        suppressions = cls()
        for number, line in enumerate(text.splitlines(), start=1):
            match = _IGNORE_RE.search(line)
            if not match:
                continue
            rules = {
                token.strip().upper()
                for token in re.split(r"[,\s]+", match.group("rules") or "")
                if token.strip()
            }
            if match.group("file"):
                suppressions.whole_file = True
                continue
            suppressions.by_line[number] = rules
        return suppressions


def apply_suppressions(
    findings: list[Finding], sources: dict[str, str]
) -> tuple[list[Finding], int]:
    """Split findings into (reported, number suppressed by inline directives)."""
    parsed = {path: Suppressions.parse(text) for path, text in sources.items()}
    kept: list[Finding] = []
    suppressed = 0
    for finding in findings:
        directives = parsed.get(finding.file)
        if directives and directives.allows(finding.rule_id, finding.line):
            suppressed += 1
        else:
            kept.append(finding)
    return kept, suppressed


class BaseScanner(ABC):
    """Common behaviour for every scanner."""

    #: Machine name, used in messages and by the CLI.
    name: str = "base"
    #: Rule category, matching :mod:`cloudguard.rules`.
    category: str = ""

    def __init__(self) -> None:
        self._lines: list[str] = []
        self._current_file: str = ""

    # -- file selection ------------------------------------------------------

    @abstractmethod
    def matches(self, path: Path) -> bool:
        """Return ``True`` when this scanner knows how to analyse ``path``."""

    def discover(self, root: Path, excludes: frozenset[str] = DEFAULT_EXCLUDES) -> list[Path]:
        """Return every file under ``root`` this scanner can analyse, sorted."""
        if root.is_file():
            return [root] if self.matches(root) else []
        found: list[Path] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in excludes for part in path.parts):
                continue
            if self.matches(path):
                found.append(path)
        return found

    # -- analysis ------------------------------------------------------------

    @abstractmethod
    def analyse(self, text: str, display_path: str) -> list[Finding]:
        """Analyse the content of one file and return its findings."""

    def analyse_files(self, sources: dict[str, str]) -> list[Finding]:
        """Analyse several files at once.

        The default implementation treats every file independently. Scanners
        needing cross-file context — Terraform, where a bucket and its
        ``public_access_block`` often live in different files — override this.
        """
        findings: list[Finding] = []
        for display_path, text in sources.items():
            findings.extend(self.analyse(text, display_path))
        return findings

    def scan_file(self, path: Path, display_path: str | None = None) -> list[Finding]:
        """Read ``path``, analyse it and drop findings covered by a suppression."""
        shown = display_path or str(path)
        text = path.read_text(encoding="utf-8", errors="replace")
        kept, _ = apply_suppressions(self.analyse_files({shown: text}), {shown: text})
        return kept

    # -- helpers for rule implementations ------------------------------------

    def set_source(self, text: str, display_path: str) -> None:
        """Remember the current file so findings can carry their source line."""
        self._lines = text.splitlines()
        self._current_file = display_path

    def snippet(self, line: int) -> str:
        """Return the trimmed source line, or ``""`` when out of range."""
        if 1 <= line <= len(self._lines):
            return self._lines[line - 1].strip()[:200]
        return ""

    def finding(
        self,
        rule_id: str,
        *,
        line: int,
        resource: str,
        message: str,
        severity: Severity | None = None,
        file: str | None = None,
    ) -> Finding:
        """Build a :class:`Finding` from the rule registry.

        ``severity`` overrides the rule default when the context justifies it —
        an open security group is CRITICAL on port 22 but HIGH on port 8080.
        """
        rule = get_rule(rule_id)
        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=severity or rule.severity,
            file=file or self._current_file,
            line=max(line, 1),
            resource=resource,
            message=message,
            remediation=rule.remediation,
            why=rule.why,
            references=rule.references,
            snippet=self.snippet(line),
            category=rule.category,
        )
