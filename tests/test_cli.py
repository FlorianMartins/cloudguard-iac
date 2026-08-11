"""End-to-end CLI tests — exit codes above all, since CI depends on them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cloudguard import __version__
from cloudguard.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app

PUBLIC_BUCKET = """
resource "aws_s3_bucket" "b" {
  bucket = "x"
  acl    = "public-read"
}
"""

LOW_ONLY = """
resource "aws_security_group" "web" {
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


class TestExitCodes:
    """The contract with CI: 0 clean, 1 blocking findings, 2 error."""

    def test_vulnerable_examples_fail(self, runner: CliRunner, vulnerable_dir: Path):
        result = runner.invoke(app, ["full-scan", str(vulnerable_dir)])
        assert result.exit_code == EXIT_FINDINGS

    def test_secure_examples_pass(self, runner: CliRunner, secure_dir: Path):
        result = runner.invoke(app, ["full-scan", str(secure_dir)])
        assert result.exit_code == EXIT_OK

    def test_missing_path_is_an_error(self, runner: CliRunner, tmp_path: Path):
        result = runner.invoke(app, ["scan-iac", str(tmp_path / "nope")])
        assert result.exit_code == EXIT_ERROR

    def test_threshold_above_the_findings_passes(self, runner: CliRunner, write_tf):
        target = write_tf(LOW_ONLY)
        assert runner.invoke(app, ["scan-iac", str(target)]).exit_code == EXIT_OK
        assert (
            runner.invoke(app, ["scan-iac", str(target), "--fail-on", "low"]).exit_code
            == EXIT_FINDINGS
        )

    def test_fail_on_never_always_passes(self, runner: CliRunner, vulnerable_dir: Path):
        result = runner.invoke(app, ["full-scan", str(vulnerable_dir), "--fail-on", "never"])
        assert result.exit_code == EXIT_OK

    def test_ignored_rule_can_unblock_a_pipeline(self, runner: CliRunner, write_tf):
        target = write_tf('resource "aws_ebs_volume" "v" {\n  size = 1\n  encrypted = false\n}\n')
        assert runner.invoke(app, ["scan-iac", str(target)]).exit_code == EXIT_FINDINGS
        assert (
            runner.invoke(app, ["scan-iac", str(target), "-i", "CG_IAC_008"]).exit_code == EXIT_OK
        )

    def test_empty_directory_passes(self, runner: CliRunner, tmp_path: Path):
        result = runner.invoke(app, ["full-scan", str(tmp_path)])
        assert result.exit_code == EXIT_OK


class TestCommands:
    def test_version(self, runner: CliRunner):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == EXIT_OK
        assert __version__ in result.stdout

    def test_help_lists_every_command(self, runner: CliRunner):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == EXIT_OK
        for command in ("scan-iac", "scan-docker", "full-scan", "generate-report", "rules"):
            assert command in result.stdout

    def test_scan_iac_only_reads_terraform(self, runner: CliRunner, vulnerable_dir: Path):
        result = runner.invoke(app, ["scan-iac", str(vulnerable_dir), "--no-color"])
        assert "main.tf" in result.stdout
        assert "CG_DOCKER" not in result.stdout

    def test_scan_docker_only_reads_dockerfiles(self, runner: CliRunner, vulnerable_dir: Path):
        result = runner.invoke(app, ["scan-docker", str(vulnerable_dir), "--no-color"])
        assert "Dockerfile" in result.stdout
        assert "CG_IAC" not in result.stdout

    def test_details_flag_prints_remediation(self, runner: CliRunner, write_tf):
        target = write_tf(PUBLIC_BUCKET)
        plain = runner.invoke(app, ["scan-iac", str(target), "--no-color"])
        detailed = runner.invoke(app, ["scan-iac", str(target), "--no-color", "--details"])
        assert len(detailed.stdout) > len(plain.stdout)
        assert "fix" in detailed.stdout

    def test_quiet_prints_nothing(self, runner: CliRunner, write_tf):
        result = runner.invoke(app, ["scan-iac", str(write_tf(PUBLIC_BUCKET)), "--quiet"])
        assert result.stdout.strip() == ""
        assert result.exit_code == EXIT_FINDINGS

    def test_rules_table(self, runner: CliRunner):
        result = runner.invoke(app, ["rules", "--no-color"])
        assert result.exit_code == EXIT_OK
        assert "CG_IAC_001" in result.stdout
        assert "CG_DOCKER_001" in result.stdout

    def test_rules_can_be_filtered(self, runner: CliRunner):
        result = runner.invoke(app, ["rules", "--category", "docker", "--no-color"])
        assert "CG_DOCKER_001" in result.stdout
        assert "CG_IAC_001" not in result.stdout

    def test_rules_rejects_an_unknown_category(self, runner: CliRunner):
        assert runner.invoke(app, ["rules", "--category", "ansible"]).exit_code == EXIT_ERROR

    def test_rules_json_is_machine_readable(self, runner: CliRunner):
        result = runner.invoke(app, ["rules", "-F", "json"])
        payload = json.loads(result.stdout)
        assert {"id", "severity", "category", "why", "remediation"} <= set(payload[0])

    def test_rules_markdown_is_a_table(self, runner: CliRunner):
        result = runner.invoke(app, ["rules", "-F", "markdown"])
        assert result.stdout.startswith("| Rule | Severity |")


class TestOutputs:
    @pytest.mark.parametrize("fmt", ["json", "markdown", "html", "sarif", "text"])
    def test_every_format_can_be_written(
        self, runner: CliRunner, write_tf, tmp_path: Path, fmt: str
    ):
        target = write_tf(PUBLIC_BUCKET)
        destination = tmp_path / f"report.{fmt}"
        result = runner.invoke(
            app, ["scan-iac", str(target), "-F", fmt, "-o", str(destination), "-q"]
        )
        assert result.exit_code == EXIT_FINDINGS
        assert destination.read_text(encoding="utf-8").strip()

    def test_extension_is_added_when_missing(self, runner: CliRunner, write_tf, tmp_path: Path):
        runner.invoke(
            app,
            [
                "scan-iac",
                str(write_tf(PUBLIC_BUCKET)),
                "-F",
                "html",
                "-o",
                str(tmp_path / "r"),
                "-q",
            ],
        )
        assert (tmp_path / "r.html").is_file()

    def test_parent_directories_are_created(self, runner: CliRunner, write_tf, tmp_path: Path):
        destination = tmp_path / "reports" / "nested" / "out.json"
        runner.invoke(
            app,
            [
                "scan-iac",
                str(write_tf(PUBLIC_BUCKET)),
                "-F",
                "json",
                "-o",
                str(destination),
                "-q",
            ],
        )
        assert destination.is_file()

    def test_json_on_stdout_is_parseable(self, runner: CliRunner, write_tf):
        result = runner.invoke(app, ["scan-iac", str(write_tf(PUBLIC_BUCKET)), "-F", "json"])
        payload = json.loads(result.stdout)
        assert payload["summary"]["total"] > 0

    def test_generate_report_round_trip(self, runner: CliRunner, write_tf, tmp_path: Path):
        results = tmp_path / "results.json"
        runner.invoke(
            app, ["scan-iac", str(write_tf(PUBLIC_BUCKET)), "-F", "json", "-o", str(results), "-q"]
        )
        report = tmp_path / "report.html"
        result = runner.invoke(
            app, ["generate-report", "-I", str(results), "-F", "html", "-o", str(report), "-q"]
        )
        assert result.exit_code == EXIT_FINDINGS
        assert "CG_IAC_001" in report.read_text(encoding="utf-8")

    def test_generate_report_rejects_a_missing_input(self, runner: CliRunner, tmp_path: Path):
        result = runner.invoke(app, ["generate-report", "-I", str(tmp_path / "nope.json")])
        assert result.exit_code == EXIT_ERROR

    def test_generate_report_rejects_invalid_json(self, runner: CliRunner, tmp_path: Path):
        broken = tmp_path / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        result = runner.invoke(app, ["generate-report", "-I", str(broken)])
        assert result.exit_code == EXIT_ERROR


class TestConfigFile:
    def test_config_is_discovered_and_applied(self, runner: CliRunner, tmp_path: Path):
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET, encoding="utf-8")
        (tmp_path / ".cloudguard.toml").write_text(
            '[cloudguard]\nfail_on = "critical"\nignore = ["CG_IAC_001"]\n', encoding="utf-8"
        )
        result = runner.invoke(app, ["scan-iac", str(tmp_path), "--no-color"])
        assert result.exit_code == EXIT_OK
        assert "CG_IAC_001" not in result.stdout

    def test_no_config_flag_restores_the_defaults(self, runner: CliRunner, tmp_path: Path):
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET, encoding="utf-8")
        (tmp_path / ".cloudguard.toml").write_text(
            '[cloudguard]\nignore = ["CG_IAC_001", "CG_IAC_002", "CG_IAC_003"]\n', encoding="utf-8"
        )
        result = runner.invoke(app, ["scan-iac", str(tmp_path), "--no-config"])
        assert result.exit_code == EXIT_FINDINGS

    def test_broken_config_is_an_error(self, runner: CliRunner, tmp_path: Path):
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET, encoding="utf-8")
        (tmp_path / ".cloudguard.toml").write_text("[cloudguard\nbroken", encoding="utf-8")
        assert runner.invoke(app, ["scan-iac", str(tmp_path)]).exit_code == EXIT_ERROR

    def test_cli_flag_wins_over_the_config(self, runner: CliRunner, tmp_path: Path):
        (tmp_path / "main.tf").write_text(PUBLIC_BUCKET, encoding="utf-8")
        (tmp_path / ".cloudguard.toml").write_text(
            '[cloudguard]\nfail_on = "never"\n', encoding="utf-8"
        )
        result = runner.invoke(app, ["scan-iac", str(tmp_path), "--fail-on", "high"])
        assert result.exit_code == EXIT_FINDINGS
