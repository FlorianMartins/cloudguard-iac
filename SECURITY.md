# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem in CloudGuard-IaC itself.

Use GitHub's private reporting — *Security* → *Report a vulnerability* on
<https://github.com/FlorianMartins/cloudguard-iac/security/advisories/new> — and include:

- the affected version and the platform,
- a minimal reproducer,
- the impact you see.

Expect an acknowledgement within 72 hours and an assessment within seven days. Fixes ship
in a patch release, credited in [CHANGELOG.md](CHANGELOG.md) unless you prefer otherwise.

## Threat model

CloudGuard-IaC reads files it does not trust: Terraform and Dockerfiles from any
repository, including a fork's pull request. Consequently:

- **It never executes what it reads.** No `eval`, no `terraform` subprocess, no
  `docker build`. Parsing is pure text analysis.
- **It never contacts the network.** No cloud API, no telemetry, no remote rule feed. A
  scan is fully offline, and the HTML report inlines its own CSS and JavaScript so it
  loads nothing either.
- **It needs no credentials.** Give it read access to files and nothing else.
- **It writes only where asked** — the path given to `--output`.

What is *in* scope for a report: a crafted input file that makes the tool hang, crash the
process in a harmful way, escape the output paths, or inject content into a generated
report (the HTML reporter escapes every value it renders — a bypass is a vulnerability).

What is *not* a vulnerability in the tool: a missed misconfiguration or a false positive.
Those are bugs — open a normal issue, they are just as welcome.

## Reports contain findings

A CloudGuard report lists the weaknesses of an infrastructure, with file names and line
numbers. Treat the artefacts as sensitive: publish them to private artefact storage, not
to a public bucket.
