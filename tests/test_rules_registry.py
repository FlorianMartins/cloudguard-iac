"""Consistency tests for the rule registry.

The registry is the single source of truth behind the CLI, the SARIF export and
the README table. These tests make sure it never drifts from the scanners.
"""

from __future__ import annotations

import re

import pytest

from cloudguard.models import SEVERITY_ORDER, Severity
from cloudguard.rules import DOCKER, RULES, TERRAFORM, all_rules, get_rule
from cloudguard.scanners.docker_scanner import DockerScanner
from cloudguard.scanners.iac_scanner import IaCScanner

ID_PATTERN = re.compile(r"^CG_(IAC|DOCKER)_\d{3}$")


@pytest.mark.parametrize("rule", RULES.values(), ids=lambda rule: rule.id)
class TestEveryRule:
    def test_id_follows_the_convention(self, rule):
        assert ID_PATTERN.match(rule.id)

    def test_id_prefix_matches_the_category(self, rule):
        expected = "CG_IAC_" if rule.category == TERRAFORM else "CG_DOCKER_"
        assert rule.id.startswith(expected)

    def test_category_is_known(self, rule):
        assert rule.category in (TERRAFORM, DOCKER)

    def test_severity_is_valid(self, rule):
        assert rule.severity in SEVERITY_ORDER

    def test_documentation_is_written(self, rule):
        """Every rule explains the impact and gives an actionable fix."""
        assert len(rule.title) > 10
        assert len(rule.why) > 60, "the 'why' must explain the impact, not restate the title"
        assert len(rule.remediation) > 30
        assert rule.remediation[0].isupper() or rule.remediation.startswith("`")

    def test_references_are_urls(self, rule):
        for reference in rule.references:
            assert reference.startswith("https://")


class TestRegistry:
    def test_ids_are_unique(self):
        assert len(RULES) == len({rule.id for rule in RULES.values()})

    def test_ids_are_contiguous(self):
        """A gap in the numbering usually means a rule was deleted by mistake."""
        for category in (TERRAFORM, DOCKER):
            numbers = sorted(
                int(rule.id.rsplit("_", 1)[1]) for rule in all_rules(category=category)
            )
            assert numbers == list(range(1, len(numbers) + 1))

    def test_titles_are_unique(self):
        titles = [rule.title for rule in RULES.values()]
        assert len(titles) == len(set(titles))

    def test_get_rule_raises_on_unknown_id(self):
        with pytest.raises(KeyError):
            get_rule("CG_IAC_999")

    def test_filtering_by_category(self):
        assert all(rule.category == DOCKER for rule in all_rules(category=DOCKER))
        assert len(all_rules()) == len(all_rules(TERRAFORM)) + len(all_rules(DOCKER))

    def test_filtering_by_severity(self):
        selected = all_rules(min_severity=Severity.HIGH)
        assert selected
        assert all(rule.severity >= Severity.HIGH for rule in selected)

    def test_both_categories_are_covered(self):
        assert len(all_rules(category=TERRAFORM)) >= 15
        assert len(all_rules(category=DOCKER)) >= 12


class TestScannerRegistryAlignment:
    """Each rule id used by a scanner must exist, and each rule must be used."""

    @staticmethod
    def _referenced_ids(source: str) -> set[str]:
        return set(re.findall(r'"(CG_(?:IAC|DOCKER)_\d{3})"', source))

    def test_iac_scanner_uses_declared_rules_only(self):
        from pathlib import Path

        source = Path(IaCScanner.__module__.replace(".", "/") + ".py").read_text(encoding="utf-8")
        for rule_id in self._referenced_ids(source):
            assert rule_id in RULES, f"{rule_id} is used by the scanner but not declared"

    def test_docker_scanner_uses_declared_rules_only(self):
        from pathlib import Path

        source = Path(DockerScanner.__module__.replace(".", "/") + ".py").read_text(
            encoding="utf-8"
        )
        for rule_id in self._referenced_ids(source):
            assert rule_id in RULES, f"{rule_id} is used by the scanner but not declared"

    def test_no_rule_is_documented_but_never_implemented(self, vulnerable_dir):
        """The vulnerable corpus is expected to trigger the whole catalogue."""
        from cloudguard import engine

        triggered = {f.rule_id for f in engine.scan_paths([vulnerable_dir]).findings}
        assert set(RULES) == triggered, sorted(set(RULES) - triggered)
