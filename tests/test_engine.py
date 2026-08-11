"""Tests for scan orchestration: discovery, suppressions, filters, results."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudguard import engine
from cloudguard.models import Finding, ScanResult, Severity
from cloudguard.scanners.base import Suppressions

PUBLIC_BUCKET = """
resource "aws_s3_bucket" "b" {
  bucket = "x"
  acl    = "public-read"
}
"""


class TestDiscovery:
    def test_directories_are_walked_recursively(self, tmp_path: Path):
        (tmp_path / "modules" / "network").mkdir(parents=True)
        (tmp_path / "modules" / "network" / "main.tf").write_text(PUBLIC_BUCKET)
        (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\n")

        result = engine.scan_paths([tmp_path])
        assert len(result.files_scanned) == 2

    def test_noise_directories_are_skipped(self, tmp_path: Path):
        (tmp_path / ".terraform" / "modules").mkdir(parents=True)
        (tmp_path / ".terraform" / "modules" / "main.tf").write_text(PUBLIC_BUCKET)
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET)

        result = engine.scan_paths([tmp_path])
        assert result.files_scanned == ["main.tf"] or len(result.files_scanned) == 1

    def test_single_file_target(self, tmp_path: Path):
        target = tmp_path / "main.tf"
        target.write_text(PUBLIC_BUCKET)
        result = engine.scan_paths([target])
        assert len(result.files_scanned) == 1

    def test_missing_path_raises(self, tmp_path: Path):
        with pytest.raises(engine.ScanTargetError):
            engine.scan_paths([tmp_path / "does-not-exist"])

    def test_unrelated_files_are_ignored(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# hello")
        result = engine.scan_paths([tmp_path])
        assert result.files_scanned == []
        assert result.is_clean


class TestFilters:
    def test_ignored_rules_are_dropped(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET)
        result = engine.scan_paths([tmp_path], ignore=["CG_IAC_001"])
        assert "CG_IAC_001" not in {f.rule_id for f in result.findings}
        assert result.findings  # the other bucket rules still fire

    def test_ignore_is_case_insensitive(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET)
        result = engine.scan_paths([tmp_path], ignore=["cg_iac_001"])
        assert "CG_IAC_001" not in {f.rule_id for f in result.findings}

    def test_excluded_paths_are_skipped(self, tmp_path: Path):
        (tmp_path / "legacy").mkdir()
        (tmp_path / "legacy" / "main.tf").write_text(PUBLIC_BUCKET)
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET)

        result = engine.scan_paths([tmp_path], exclude=["legacy"], root=tmp_path)
        assert result.files_scanned == ["main.tf"]


class TestSuppressions:
    def test_inline_directive_on_the_same_line(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "b" {\n'
            '  acl = "public-read"  # cloudguard:ignore CG_IAC_001\n'
            "}\n"
        )
        result = engine.scan_paths([tmp_path])
        assert "CG_IAC_001" not in {f.rule_id for f in result.findings}
        assert result.suppressed == 1

    def test_directive_on_the_previous_line(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            "# cloudguard:ignore CG_IAC_001\n"
            'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
        )
        # The directive covers the resource line, not the acl line two rows below.
        suppressions = Suppressions.parse(
            '# cloudguard:ignore CG_IAC_001\nresource "aws_s3_bucket" "b" {\n'
        )
        assert suppressions.allows("CG_IAC_001", 2)
        assert not suppressions.allows("CG_IAC_002", 2)

    def test_bare_directive_suppresses_every_rule(self):
        suppressions = Suppressions.parse('acl = "public-read" # cloudguard:ignore\n')
        assert suppressions.allows("CG_IAC_001", 1)
        assert suppressions.allows("CG_IAC_999", 1)

    def test_file_level_directive(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text("# cloudguard:ignore-file\n" + PUBLIC_BUCKET)
        result = engine.scan_paths([tmp_path])
        assert result.findings == []
        assert result.suppressed > 0

    def test_directive_with_several_rules(self):
        suppressions = Suppressions.parse("# cloudguard:ignore CG_IAC_001, CG_IAC_002\n")
        assert suppressions.allows("CG_IAC_001", 1)
        assert suppressions.allows("CG_IAC_002", 1)
        assert not suppressions.allows("CG_IAC_003", 1)


class TestScanResult:
    def _result(self) -> ScanResult:
        result = ScanResult(tool_version="1.0.0")
        result.extend(
            [
                Finding("CG_IAC_001", "t", Severity.CRITICAL, "a.tf", 3, "r", "m"),
                Finding("CG_IAC_002", "t", Severity.HIGH, "a.tf", 1, "r", "m"),
                Finding("CG_DOCKER_011", "t", Severity.LOW, "Dockerfile", 2, "r", "m"),
            ]
        )
        return result

    def test_counts_and_max_severity(self):
        result = self._result()
        counts = result.counts()
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.MEDIUM] == 0
        assert result.max_severity is Severity.CRITICAL
        assert result.count_at_or_above(Severity.HIGH) == 2
        assert result.count_at_or_above(Severity.LOW) == 3

    def test_findings_sort_by_severity_then_location(self):
        ordered = self._result().sorted_findings()
        assert [f.rule_id for f in ordered] == ["CG_IAC_001", "CG_IAC_002", "CG_DOCKER_011"]

    def test_round_trip_through_json(self):
        result = self._result()
        restored = ScanResult.from_dict(result.to_dict())
        assert [f.to_dict() for f in restored.sorted_findings()] == [
            f.to_dict() for f in result.sorted_findings()
        ]

    def test_group_by_file(self):
        grouped = engine.group_by_file(self._result().findings)
        assert set(grouped) == {"a.tf", "Dockerfile"}
        assert [f.rule_id for f in grouped["a.tf"]] == ["CG_IAC_001", "CG_IAC_002"]

    def test_empty_result_is_clean(self):
        result = ScanResult()
        assert result.is_clean
        assert result.max_severity is None
        assert result.count_at_or_above(Severity.INFO) == 0


class TestSeverity:
    def test_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
        assert Severity.HIGH >= Severity.HIGH
        assert Severity.LOW < Severity.CRITICAL

    def test_parse_is_case_insensitive(self):
        assert Severity.parse("high") is Severity.HIGH
        assert Severity.parse("  Critical ") is Severity.CRITICAL

    def test_parse_rejects_unknown(self):
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("catastrophic")
