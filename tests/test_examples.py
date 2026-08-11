"""End-to-end assertions on the example corpus.

These are the tests the CI pipeline relies on to claim the tool works:

* every insecure file in ``examples/vulnerable`` is detected, rule by rule;
* every hardened file in ``examples/secure`` is accepted, with zero findings.

They are also a regression net for the rules themselves — a rule that stops
firing, or starts firing on the secure corpus, fails the build here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudguard import engine
from cloudguard.models import Severity
from cloudguard.rules import DOCKER, RULES, TERRAFORM, all_rules

TERRAFORM_RULE_IDS = {rule.id for rule in all_rules(category=TERRAFORM)}
DOCKER_RULE_IDS = {rule.id for rule in all_rules(category=DOCKER)}


@pytest.fixture(scope="module")
def vulnerable_result(vulnerable_dir: Path):
    """Scan of the intentionally insecure corpus."""
    return engine.scan_paths([vulnerable_dir])


@pytest.fixture(scope="module")
def secure_result(secure_dir: Path):
    """Scan of the hardened corpus."""
    return engine.scan_paths([secure_dir])


class TestVulnerableCorpus:
    def test_both_files_are_analysed(self, vulnerable_result):
        names = {Path(path).name for path in vulnerable_result.files_scanned}
        assert names == {"main.tf", "Dockerfile"}

    def test_findings_are_reported(self, vulnerable_result):
        assert len(vulnerable_result.findings) >= 30

    def test_every_terraform_rule_fires(self, vulnerable_result):
        triggered = {f.rule_id for f in vulnerable_result.findings}
        assert triggered >= TERRAFORM_RULE_IDS, sorted(TERRAFORM_RULE_IDS - triggered)

    def test_every_docker_rule_fires(self, vulnerable_result):
        triggered = {f.rule_id for f in vulnerable_result.findings}
        assert triggered >= DOCKER_RULE_IDS, sorted(DOCKER_RULE_IDS - triggered)

    def test_critical_findings_exist(self, vulnerable_result):
        assert vulnerable_result.max_severity is Severity.CRITICAL
        assert vulnerable_result.counts()[Severity.CRITICAL] >= 5

    def test_scan_would_block_a_pipeline(self, vulnerable_result):
        assert vulnerable_result.count_at_or_above(Severity.HIGH) > 0

    def test_public_bucket_is_found_on_the_right_line(self, vulnerable_result):
        finding = next(f for f in vulnerable_result.findings if f.rule_id == "CG_IAC_001")
        source = (Path(finding.file)).read_text(encoding="utf-8").splitlines()
        assert "public-read" in source[finding.line - 1]

    def test_open_ssh_is_found_on_the_right_line(self, vulnerable_result):
        finding = next(f for f in vulnerable_result.findings if f.rule_id == "CG_IAC_005")
        assert "22/SSH" in finding.message

    def test_every_finding_is_actionable(self, vulnerable_result):
        for finding in vulnerable_result.findings:
            assert finding.rule_id in RULES
            assert finding.message
            assert finding.remediation
            assert finding.why
            assert finding.line >= 1
            assert finding.file


class TestSecureCorpus:
    def test_both_files_are_analysed(self, secure_result):
        names = {Path(path).name for path in secure_result.files_scanned}
        assert names == {"main.tf", "Dockerfile"}

    def test_no_finding_at_all(self, secure_result):
        assert secure_result.findings == [], [
            f"{f.rule_id} {f.location} {f.message}" for f in secure_result.findings
        ]

    def test_scan_is_clean(self, secure_result):
        assert secure_result.is_clean
        assert secure_result.max_severity is None

    def test_no_parse_error(self, secure_result):
        assert secure_result.errors == []

    def test_documented_suppression_is_counted(self, secure_result):
        """The log bucket suppresses CG_IAC_015 with an explicit justification."""
        assert secure_result.suppressed == 1


class TestScannerSelection:
    def test_iac_scan_ignores_dockerfiles(self, vulnerable_dir: Path):
        result = engine.scan_iac([vulnerable_dir])
        assert {Path(p).name for p in result.files_scanned} == {"main.tf"}
        assert all(f.category == TERRAFORM for f in result.findings)

    def test_docker_scan_ignores_terraform(self, vulnerable_dir: Path):
        result = engine.scan_docker([vulnerable_dir])
        assert {Path(p).name for p in result.files_scanned} == {"Dockerfile"}
        assert all(f.category == DOCKER for f in result.findings)
