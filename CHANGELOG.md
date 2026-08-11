# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [1.0.0] — 2026-08-11

First public release.

### Added

- **CLI** built on Typer with five commands — `scan-iac`, `scan-docker`, `full-scan`,
  `generate-report` and `rules` — and CI-friendly exit codes (`0` clean, `1` blocking
  findings, `2` error), driven by `--fail-on`.
- **Terraform scanner** with a dependency-free HCL2 parser (blocks, attributes, literals,
  heredocs, comments, interpolations) and **17 rules** covering S3 exposure and encryption,
  security groups, EBS/EFS/RDS encryption, public databases, backups, IMDSv2, wildcard IAM
  policies and hardcoded secrets. Companion resources declared in other files
  (`aws_s3_bucket_public_access_block` and friends) are resolved through a module-wide index.
- **Dockerfile scanner** with an instruction model (line continuations, heredocs, `escape`
  directive, multi-stage awareness) and **14 rules** covering root execution, unpinned base
  images, exposed administration ports, `curl | sh`, baked secrets, `ADD` from a URL, sudo,
  `chmod 777`, unpinned dependencies, package caches, missing `HEALTHCHECK` and full-context
  `COPY`.
- **Reporters**: Rich console output, Markdown (pull requests and job summaries),
  self-contained HTML dashboard with severity filters and live search, JSON, and
  **SARIF 2.1.0** for GitHub code scanning.
- **Suppressions**: inline `# cloudguard:ignore RULE_ID`, `# cloudguard:ignore-file`, plus
  `--ignore` and `--exclude`. Suppressed findings are counted and displayed, never hidden.
- **Configuration** through `.cloudguard.toml`, discovered upwards from the scanned path,
  always overridable from the command line.
- **Example corpus**: `examples/vulnerable/` triggers all 31 rules, `examples/secure/`
  triggers none — both asserted by the test suite.
- **CI/CD**: GitHub Actions pipeline (lint, strict types, tests on Python 3.10 → 3.13,
  bandit, pip-audit, semgrep, self-scan, packaging, container build) and a reusable
  composite action.
- **Container image**: multi-stage, non-root (uid 10001), scanned by the tool itself.
- Documentation: README with the generated rules catalogue, CONTRIBUTING, SECURITY.

[Unreleased]: https://github.com/FlorianMartins/cloudguard-iac/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/FlorianMartins/cloudguard-iac/releases/tag/v1.0.0
