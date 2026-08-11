"""Tests for the report renderers."""

from __future__ import annotations

import json
import re
from html import escape
from html.parser import HTMLParser
from typing import ClassVar

import pytest

from cloudguard import reporters
from cloudguard.models import Finding, ScanResult, Severity
from cloudguard.reporters import html_reporter, markdown_reporter, sarif_reporter
from cloudguard.rules import RULES


@pytest.fixture
def result() -> ScanResult:
    """A small result covering two files and three severities."""
    scan = ScanResult(
        tool_version="1.0.0",
        target="examples/vulnerable",
        files_scanned=["main.tf", "Dockerfile"],
        duration_seconds=0.42,
    )
    scan.extend(
        [
            Finding(
                rule_id="CG_IAC_001",
                title=RULES["CG_IAC_001"].title,
                severity=Severity.CRITICAL,
                file="main.tf",
                line=12,
                resource="aws_s3_bucket.data",
                message='bucket ACL is "public-read"',
                remediation=RULES["CG_IAC_001"].remediation,
                why=RULES["CG_IAC_001"].why,
                references=RULES["CG_IAC_001"].references,
                snippet='acl = "public-read"',
                category="terraform",
            ),
            Finding(
                rule_id="CG_DOCKER_001",
                title=RULES["CG_DOCKER_001"].title,
                severity=Severity.HIGH,
                file="Dockerfile",
                line=3,
                resource="ubuntu:latest",
                message="no USER instruction",
                remediation=RULES["CG_DOCKER_001"].remediation,
                why=RULES["CG_DOCKER_001"].why,
                snippet="FROM ubuntu:latest",
                category="docker",
            ),
            Finding(
                rule_id="CG_DOCKER_011",
                title=RULES["CG_DOCKER_011"].title,
                severity=Severity.LOW,
                file="Dockerfile",
                line=3,
                resource="ubuntu:latest",
                message="no HEALTHCHECK",
                category="docker",
            ),
        ]
    )
    return scan


@pytest.fixture
def clean_result() -> ScanResult:
    """A result with no finding."""
    return ScanResult(tool_version="1.0.0", files_scanned=["main.tf"], target=".")


class _TagBalanceChecker(HTMLParser):
    """Minimal well-formedness check for the generated HTML."""

    VOID: ClassVar[set[str]] = {"meta", "br", "hr", "img", "input", "link"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.errors: list[str] = []

    def handle_starttag(self, tag: str, _attrs: list) -> None:
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}>, open: {self.stack[-3:]}")
            return
        self.stack.pop()


class TestJson:
    def test_structure(self, result: ScanResult):
        payload = json.loads(reporters.render(result, "json", threshold=Severity.HIGH))
        assert payload["schema"] == "cloudguard.scan-result/v1"
        assert payload["summary"]["total"] == 3
        assert payload["summary"]["by_severity"]["CRITICAL"] == 1
        assert payload["summary"]["blocking"] == 2
        assert payload["summary"]["fail_on"] == "HIGH"
        assert len(payload["findings"]) == 3

    def test_findings_are_sorted_by_severity(self, result: ScanResult):
        payload = json.loads(reporters.render(result, "json"))
        assert [f["severity"] for f in payload["findings"]] == ["CRITICAL", "HIGH", "LOW"]

    def test_round_trip(self, result: ScanResult):
        payload = json.loads(reporters.render(result, "json"))
        restored = ScanResult.from_dict(payload)
        assert len(restored.findings) == 3
        assert restored.tool_version == "1.0.0"


class TestMarkdown:
    def test_contains_summary_and_details(self, result: ScanResult):
        report = markdown_reporter.render(result, threshold=Severity.HIGH)
        assert "# 🛡️ CloudGuard-IaC" in report
        assert "| Severity | Count |" in report
        assert "CG_IAC_001" in report
        assert "Pipeline blocked" in report
        assert RULES["CG_IAC_001"].remediation[:40] in report

    def test_clean_result(self, clean_result: ScanResult):
        report = markdown_reporter.render(clean_result, threshold=Severity.HIGH)
        assert "No security issue detected" in report
        assert "Pipeline blocked" not in report

    def test_pipes_are_escaped(self):
        scan = ScanResult(tool_version="1.0.0")
        scan.add(
            Finding("CG_IAC_001", "t", Severity.LOW, "a.tf", 1, "r", "a | b", category="terraform")
        )
        report = markdown_reporter.render(scan)
        table_row = next(line for line in report.splitlines() if "a \\| b" in line)
        # The escaped pipe must not be read as a column separator: five columns
        # means six separators, plus the escaped one inside the cell.
        assert len(re.findall(r"(?<!\\)\|", table_row)) == 6

    def test_advisory_when_below_threshold(self, result: ScanResult):
        report = markdown_reporter.render(result, threshold=Severity.CRITICAL)
        assert "Pipeline blocked" in report  # one CRITICAL finding is present


class TestHtml:
    def test_is_self_contained(self, result: ScanResult):
        page = html_reporter.render(result, threshold=Severity.HIGH)
        assert page.startswith("<!DOCTYPE html>")
        assert "<style>" in page and "<script>" in page
        # CSS and JS are inlined: nothing is fetched from the network. Anchors
        # pointing at vendor documentation are fine — they are links, not loads.
        assert "<link " not in page
        assert not re.search(r"<(?:script|img|iframe)[^>]*\ssrc\s*=", page)

    def test_is_well_formed(self, result: ScanResult):
        checker = _TagBalanceChecker()
        checker.feed(html_reporter.render(result))
        assert checker.errors == []
        assert checker.stack == []

    def test_shows_every_finding(self, result: ScanResult):
        page = html_reporter.render(result)
        for finding in result.findings:
            assert finding.rule_id in page
            assert escape(finding.message) in page

    def test_user_content_is_escaped(self):
        scan = ScanResult(tool_version="1.0.0")
        scan.add(
            Finding(
                "CG_IAC_001",
                "t",
                Severity.LOW,
                "a.tf",
                1,
                '<img src=x onerror="alert(1)">',
                "message",
                snippet="<script>alert(1)</script>",
            )
        )
        page = html_reporter.render(scan)
        # The only <script> tag left is the report's own inline behaviour.
        assert page.count("<script>") == 1
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
        assert "<img" not in page
        assert 'onerror="' not in page  # the quote that would break out is escaped

    def test_clean_result_shows_success(self, clean_result: ScanResult):
        page = html_reporter.render(clean_result, threshold=Severity.HIGH)
        assert "No security issue detected" in page
        assert "All clear" in page


class TestSarif:
    def test_schema_and_structure(self, result: ScanResult):
        document = json.loads(sarif_reporter.render(result))
        assert document["version"] == "2.1.0"
        run = document["runs"][0]
        assert run["tool"]["driver"]["name"] == "CloudGuard-IaC"
        assert len(run["results"]) == 3

    def test_only_used_rules_are_declared(self, result: ScanResult):
        run = json.loads(sarif_reporter.render(result))["runs"][0]
        declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        assert declared == {"CG_IAC_001", "CG_DOCKER_001", "CG_DOCKER_011"}

    def test_levels_and_locations(self, result: ScanResult):
        run = json.loads(sarif_reporter.render(result))["runs"][0]
        first = run["results"][0]
        assert first["level"] == "error"
        location = first["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == "main.tf"
        assert location["region"]["startLine"] == 12
        assert first["properties"]["security-severity"] == "9.5"

    def test_every_registry_rule_can_be_described(self):
        """A rule missing from the registry would break the SARIF upload."""
        scan = ScanResult(tool_version="1.0.0")
        for rule in RULES.values():
            scan.add(
                Finding(
                    rule.id, rule.title, rule.severity, "f", 1, "r", "m", category=rule.category
                )
            )
        run = json.loads(sarif_reporter.render(scan))["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) == len(RULES)


class TestText:
    def test_text_report_mentions_findings(self, result: ScanResult):
        report = reporters.render(result, "text", threshold=Severity.HIGH)
        assert "CG_IAC_001" in report
        assert "FAILED" in report

    def test_text_report_of_a_clean_scan(self, clean_result: ScanResult):
        report = reporters.render(clean_result, "text", threshold=Severity.HIGH)
        assert "PASSED" in report
        assert "no findings" in report


def test_every_format_is_renderable(result: ScanResult):
    for fmt in reporters.FORMATS:
        content = reporters.render(result, fmt, threshold=Severity.HIGH)
        assert content.strip()
        assert fmt in reporters.EXTENSIONS
