"""SARIF 2.1.0 reporter — feeds GitHub code scanning and any SARIF viewer.

Uploading this file with ``github/codeql-action/upload-sarif`` makes every
CloudGuard finding appear as a native code-scanning alert, annotated on the exact
line of the pull request diff.
"""

from __future__ import annotations

import json
from typing import Any

from cloudguard.models import ScanResult, Severity
from cloudguard.rules import RULES

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

#: SARIF only knows error/warning/note; keep the real severity in properties.
_LEVELS: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

#: GitHub reads security-severity as a CVSS-like score to rank alerts.
_SECURITY_SCORE: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _rule_descriptor(rule_id: str) -> dict[str, Any]:
    rule = RULES[rule_id]
    return {
        "id": rule.id,
        "name": "".join(word.capitalize() for word in rule.title.split()),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.why},
        "help": {
            "text": f"{rule.why}\n\nRemediation: {rule.remediation}",
            "markdown": (
                f"**Why it matters** — {rule.why}\n\n"
                f"**Remediation** — {rule.remediation}\n\n"
                + (
                    "**References**\n" + "\n".join(f"- {r}" for r in rule.references)
                    if rule.references
                    else ""
                )
            ),
        },
        "defaultConfiguration": {"level": _LEVELS[rule.severity]},
        "properties": {
            "tags": ["security", rule.category, f"severity/{rule.severity.value.lower()}"],
            "precision": "high",
            "security-severity": _SECURITY_SCORE[rule.severity],
        },
    }


def render(result: ScanResult, *, threshold: Severity | None = None) -> str:  # noqa: ARG001
    """Render a scan result as a SARIF 2.1.0 document."""
    used_rules = sorted({f.rule_id for f in result.findings if f.rule_id in RULES})
    results = [
        {
            "ruleId": finding.rule_id,
            "level": _LEVELS[finding.severity],
            "message": {"text": f"{finding.title}: {finding.message}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file, "uriBaseId": "%SRCROOT%"},
                        "region": {
                            "startLine": max(finding.line, 1),
                            "snippet": {"text": finding.snippet} if finding.snippet else {},
                        },
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "resource": finding.resource,
                "security-severity": _SECURITY_SCORE[finding.severity],
            },
            "partialFingerprints": {
                "cloudguard/v1": f"{finding.rule_id}:{finding.file}:{finding.resource}",
            },
        }
        for finding in result.sorted_findings()
    ]

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CloudGuard-IaC",
                        "semanticVersion": result.tool_version,
                        "version": result.tool_version,
                        "informationUri": "https://github.com/FlorianMartins/cloudguard-iac",
                        "rules": [_rule_descriptor(rule_id) for rule_id in used_rules],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": error}}
                            for error in result.errors
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False)
