## What this changes

<!-- One or two sentences. Link the issue it closes: Closes #123 -->

## Why

<!-- The problem being solved. For a new rule: the impact of the misconfiguration. -->

## Checklist

- [ ] `make check` is green (lint, types, tests, SAST, self-scan, docs)
- [ ] New behaviour is covered by a test
- [ ] For a new rule:
  - [ ] declared in `cloudguard/rules.py` with an impact-oriented `why` and an actionable `remediation`
  - [ ] the insecure pattern added to `examples/vulnerable/` **and** its fix to `examples/secure/`
  - [ ] **both** a positive and a negative test — a rule with no negative test is a future false positive
  - [ ] `make docs` run, so the README table matches the registry
- [ ] For a behaviour change: `CHANGELOG.md` updated under `[Unreleased]`

## How it was verified

<!-- The commands you ran and what they returned. "Tests pass" is not a verification. -->
