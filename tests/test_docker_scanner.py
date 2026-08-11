"""Rule-by-rule tests for the Dockerfile scanner."""

from __future__ import annotations

import pytest

from cloudguard.models import Severity
from cloudguard.scanners.docker_scanner import DockerScanner, parse_dockerfile, split_stages

#: A minimal compliant image, used as the baseline every test mutates.
CLEAN = """
FROM python:3.12-slim
RUN apt-get update \\
 && apt-get install -y --no-install-recommends curl=7.88.1-10 \\
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/ ./src/
USER 10001
HEALTHCHECK CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["python", "-m", "src.server"]
"""


def scan(source: str) -> list:
    """Analyse a Dockerfile and return its findings."""
    return DockerScanner().analyse(source, "Dockerfile")


def rule_ids(source: str) -> set[str]:
    """Rule ids triggered by a Dockerfile."""
    return {finding.rule_id for finding in scan(source)}


class TestParser:
    def test_line_continuations_are_joined(self):
        instructions = parse_dockerfile("RUN apt-get update \\\n && apt-get install -y curl\n")
        assert len(instructions) == 1
        assert instructions[0].keyword == "RUN"
        assert "apt-get install" in instructions[0].value
        assert instructions[0].line == 1

    def test_comments_and_blank_lines_are_skipped(self):
        instructions = parse_dockerfile("# comment\n\nFROM alpine:3.20\n")
        assert [i.keyword for i in instructions] == ["FROM"]
        assert instructions[0].line == 3

    def test_stages_are_split_with_aliases(self):
        stages = split_stages(
            parse_dockerfile("FROM golang:1.22 AS builder\nRUN go build\nFROM alpine:3.20\n")
        )
        assert [s.alias for s in stages] == ["builder", ""]
        assert [s.image for s in stages] == ["golang:1.22", "alpine:3.20"]
        assert len(stages[0].instructions) == 1

    def test_heredoc_body_is_absorbed(self):
        instructions = parse_dockerfile("RUN <<EOF\napt-get update\nEOF\nUSER app\n")
        assert [i.keyword for i in instructions] == ["RUN", "USER"]
        assert "apt-get update" in instructions[0].value


class TestUserRule:
    def test_missing_user_is_high(self):
        findings = [
            f for f in scan('FROM python:3.12-slim\nCMD ["app"]\n') if f.rule_id == "CG_DOCKER_001"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH

    @pytest.mark.parametrize("user", ["root", "0"])
    def test_explicit_root_is_reported(self, user: str):
        assert "CG_DOCKER_001" in rule_ids(f"FROM python:3.12-slim\nUSER {user}\n")

    def test_unprivileged_user_is_clean(self):
        assert "CG_DOCKER_001" not in rule_ids("FROM python:3.12-slim\nUSER app\n")

    def test_root_in_a_builder_stage_is_not_reported(self):
        """Only the final stage ships, so root in a builder is irrelevant."""
        source = """
        FROM python:3.12-slim AS builder
        USER root
        RUN pip wheel -r requirements.txt

        FROM python:3.12-slim AS runtime
        USER 10001
        HEALTHCHECK CMD exit 0
        """
        assert "CG_DOCKER_001" not in rule_ids(source)

    def test_user_inherited_from_the_parent_stage(self):
        source = """
        FROM python:3.12-slim AS base
        USER 10001
        HEALTHCHECK CMD exit 0

        FROM base AS runtime
        COPY src/ ./src/
        """
        assert "CG_DOCKER_001" not in rule_ids(source)


class TestBaseImageRule:
    def test_latest_tag_is_reported(self):
        assert "CG_DOCKER_002" in rule_ids("FROM ubuntu:latest\nUSER app\n")

    def test_missing_tag_is_reported(self):
        assert "CG_DOCKER_002" in rule_ids("FROM ubuntu\nUSER app\n")

    def test_pinned_tag_is_clean(self):
        assert "CG_DOCKER_002" not in rule_ids("FROM ubuntu:24.04\nUSER app\n")

    def test_digest_is_clean(self):
        assert "CG_DOCKER_002" not in rule_ids("FROM ubuntu@sha256:" + "a" * 64 + "\nUSER app\n")

    def test_scratch_is_clean(self):
        assert "CG_DOCKER_002" not in rule_ids("FROM scratch\nUSER app\n")

    def test_stage_reference_is_not_an_image(self):
        source = "FROM golang:1.22 AS builder\nFROM builder AS final\nUSER app\n"
        assert "CG_DOCKER_002" not in rule_ids(source)

    def test_build_arg_image_is_skipped(self):
        assert "CG_DOCKER_002" not in rule_ids("ARG BASE\nFROM ${BASE}\nUSER app\n")


class TestSecretRules:
    def test_env_password_is_critical(self):
        findings = [
            f
            for f in scan("FROM alpine:3.20\nENV DB_PASSWORD=hunter2\n")
            if f.rule_id == "CG_DOCKER_005"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_recognisable_token_is_detected(self):
        assert "CG_DOCKER_005" in rule_ids(
            "FROM alpine:3.20\nARG TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"
        )

    def test_aws_key_in_a_run_command(self):
        assert "CG_DOCKER_005" in rule_ids(
            "FROM alpine:3.20\nRUN aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE\n"
        )

    def test_runtime_placeholder_is_clean(self):
        assert "CG_DOCKER_005" not in rule_ids("FROM alpine:3.20\nENV DB_PASSWORD=$DB_PASSWORD\n")

    def test_empty_build_arg_is_clean(self):
        assert "CG_DOCKER_005" not in rule_ids("FROM alpine:3.20\nARG API_TOKEN\n")

    def test_unrelated_env_is_clean(self):
        assert "CG_DOCKER_005" not in rule_ids("FROM alpine:3.20\nENV PORT=8080\n")


class TestCommandRules:
    def test_exposed_ssh_port(self):
        findings = [
            f for f in scan("FROM alpine:3.20\nEXPOSE 22\n") if f.rule_id == "CG_DOCKER_003"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH

    def test_regular_port_is_clean(self):
        assert "CG_DOCKER_003" not in rule_ids("FROM alpine:3.20\nEXPOSE 8080/tcp\n")

    def test_curl_piped_into_shell(self):
        assert "CG_DOCKER_004" in rule_ids(
            "FROM alpine:3.20\nRUN curl -fsSL https://example.com/i.sh | sh\n"
        )

    def test_verified_download_is_clean(self):
        assert "CG_DOCKER_004" not in rule_ids(
            "FROM alpine:3.20\n"
            "RUN curl -fsSLo i.sh https://example.com/i.sh "
            '&& echo "abc  i.sh" | sha256sum -c - && ./i.sh\n'
        )

    def test_add_with_url(self):
        assert "CG_DOCKER_006" in rule_ids(
            "FROM alpine:3.20\nADD https://example.com/a.tgz /opt/a.tgz\n"
        )

    def test_add_with_local_file_is_clean(self):
        assert "CG_DOCKER_006" not in rule_ids("FROM alpine:3.20\nADD app.tgz /opt/\n")

    def test_sudo_is_reported(self):
        assert "CG_DOCKER_007" in rule_ids("FROM alpine:3.20\nRUN apk add sudo\n")

    def test_chmod_777_is_reported(self):
        assert "CG_DOCKER_008" in rule_ids("FROM alpine:3.20\nRUN chmod -R 777 /app\n")

    def test_restrictive_chmod_is_clean(self):
        assert "CG_DOCKER_008" not in rule_ids("FROM alpine:3.20\nRUN chmod 550 /app\n")

    @pytest.mark.parametrize(
        "command,expected",
        [
            ("RUN pip install flask", True),
            ("RUN pip install flask==3.0.0", False),
            ("RUN pip install -r requirements.txt", False),
            ("RUN npm install express", True),
            ("RUN npm install express@4.19.2", False),
        ],
    )
    def test_dependency_pinning(self, command: str, expected: bool):
        assert ("CG_DOCKER_009" in rule_ids(f"FROM alpine:3.20\n{command}\n")) is expected

    def test_apt_without_cleanup(self):
        assert "CG_DOCKER_010" in rule_ids("FROM debian:12\nRUN apt-get install -y curl\n")

    def test_apt_with_cleanup_is_clean(self):
        assert "CG_DOCKER_010" not in rule_ids(
            "FROM debian:12\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends curl=1 "
            "&& rm -rf /var/lib/apt/lists/*\n"
        )

    def test_apk_without_no_cache(self):
        assert "CG_DOCKER_010" in rule_ids("FROM alpine:3.20\nRUN apk add curl\n")

    def test_copy_whole_context(self):
        assert "CG_DOCKER_012" in rule_ids("FROM alpine:3.20\nCOPY . .\n")

    def test_scoped_copy_is_clean(self):
        assert "CG_DOCKER_012" not in rule_ids("FROM alpine:3.20\nCOPY src/ ./src/\n")

    def test_copy_from_a_stage_is_clean(self):
        assert "CG_DOCKER_012" not in rule_ids(
            "FROM alpine:3.20 AS b\nFROM alpine:3.20\nCOPY --from=b /install /usr/local\n"
        )

    def test_maintainer_is_info(self):
        findings = [
            f
            for f in scan("FROM alpine:3.20\nMAINTAINER me@example.com\n")
            if f.rule_id == "CG_DOCKER_013"
        ]
        assert findings[0].severity is Severity.INFO

    def test_apt_upgrade_is_reported(self):
        assert "CG_DOCKER_014" in rule_ids("FROM debian:12\nRUN apt-get upgrade -y\n")


class TestHealthcheck:
    def test_missing_healthcheck(self):
        assert "CG_DOCKER_011" in rule_ids("FROM alpine:3.20\nUSER app\n")

    def test_healthcheck_none_does_not_count(self):
        assert "CG_DOCKER_011" in rule_ids("FROM alpine:3.20\nUSER app\nHEALTHCHECK NONE\n")

    def test_healthcheck_present(self):
        assert "CG_DOCKER_011" not in rule_ids(
            "FROM alpine:3.20\nUSER app\nHEALTHCHECK CMD exit 0\n"
        )


class TestScannerBehaviour:
    def test_clean_dockerfile_has_no_finding(self):
        assert scan(CLEAN) == []

    def test_findings_are_sorted_by_line(self):
        findings = scan("FROM ubuntu:latest\nEXPOSE 22\nRUN chmod 777 /app\n")
        assert [f.line for f in findings] == sorted(f.line for f in findings)

    def test_empty_file_is_handled(self):
        assert scan("# nothing here\n") == []

    def test_matches_dockerfile_names(self, tmp_path):
        scanner = DockerScanner()
        assert scanner.matches(tmp_path / "Dockerfile")
        assert scanner.matches(tmp_path / "Dockerfile.prod")
        assert scanner.matches(tmp_path / "api.dockerfile")
        assert not scanner.matches(tmp_path / "docker-compose.yml")
