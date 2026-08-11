# Contributing to CloudGuard-IaC

Thanks for taking the time. A new rule, a false positive killed, a clearer remediation —
all three make the tool more useful.

## Getting set up

```bash
git clone https://github.com/FlorianMartins/cloudguard-iac.git
cd cloudguard-iac
make install            # virtualenv + editable install with the dev extras
make check              # lint + types + tests + SAST + self-scan
```

Optionally install the local guardrails so the same gates run before each commit:

```bash
pip install pre-commit && pre-commit install
```

## The bar for a pull request

`make check` must be green. It runs exactly what the CI pipeline runs:

| Gate | Command | Rule |
|---|---|---|
| Lint & format | `make lint` | `ruff check` and `ruff format --check`, no exception |
| Types | `make typecheck` | `mypy --strict`, no `Any` sneaking in |
| Tests | `make test` | Every new behaviour has a test; coverage must not go down |
| SAST | `make sast` | `bandit` and `pip-audit` clean |
| Self-scan | `make selfscan` | CloudGuard accepts its own repository |
| Docs | `make docs-check` | The README rules table matches the registry |

## Adding a detection rule

A rule is five small steps, in this order:

1. **Declare it** in [`cloudguard/rules.py`](cloudguard/rules.py): id, severity, category,
   `why` and `remediation`.
   - The id follows `CG_IAC_0NN` / `CG_DOCKER_0NN` and takes the next free number.
   - `why` explains the **impact** — what an attacker gains, what a breach costs. Not a
     restatement of the title.
   - `remediation` is **actionable**: the attribute to set, the resource to add, the
     command to run.
   - Add a reference (vendor documentation, CIS benchmark, CWE) when there is a good one.

2. **Implement the detection** in `scanners/iac_scanner.py` or `scanners/docker_scanner.py`,
   returning `self.finding("CG_…", line=…, resource=…, message=…)`. The message says what
   *this* occurrence is, in one sentence, lowercase, no trailing period.

3. **Extend the corpus**: the vulnerable pattern in `examples/vulnerable/`, its fix in
   `examples/secure/`. The registry test refuses a rule that never fires on the vulnerable
   corpus, and the example test refuses one that fires on the secure corpus.

4. **Write both tests** in `tests/test_iac_scanner.py` or `tests/test_docker_scanner.py`:
   - the positive case — the rule fires, with the expected severity;
   - the negative case — a correct configuration stays clean.

   A rule with no negative test is a future false positive.

5. **Refresh the docs**: `make docs`, then `make check`.

### Choosing a severity

| Severity | Criterion |
|---|---|
| **CRITICAL** | Directly exploitable from the Internet, or leaks a live credential. Public bucket, SSH open to `0.0.0.0/0`, hardcoded password. |
| **HIGH** | Removes a layer of defence, or exposes data if another control fails. No encryption, wildcard IAM, container running as root. |
| **MEDIUM** | Meaningfully increases the blast radius or breaks reproducibility. IMDSv1, unpinned base image, no backups. |
| **LOW** | Hardening and hygiene. Missing logging, unpinned dependencies, leftover package caches. |
| **INFO** | Good practice, never a vulnerability. Deprecated instructions. |

When hesitating between two levels, ask what the *cheapest* exploitation path costs. The
default threshold is `HIGH`, so a rule declared HIGH will block other people's pipelines —
that is a decision, not a detail.

## Reporting a false positive

False positives are bugs, and they are the worst kind: a tool that cries wolf gets
ignored, and an ignored tool protects nothing. Open an issue with:

- the smallest snippet that reproduces it,
- the rule id,
- what the correct verdict is, and why.

## Commit style

Conventional Commits, in the imperative:

```
feat(rules): detect unencrypted EFS file systems (CG_IAC_018)
fix(hcl): stop swallowing the attribute after a heredoc
docs(readme): document the rollout strategy
test(docker): cover the multi-stage USER inheritance
```

## Code conventions

- Docstrings on every public module, class and function (Google style, enforced by ruff).
- Comments explain **why**, never what the line already says.
- No new runtime dependency without a discussion: staying installable in seconds in any
  runner is a feature.
- Data model in `models.py`, documentation in `rules.py`, detection in `scanners/`,
  presentation in `reporters/`. A scanner that formats a report, or a reporter that
  decides a severity, is in the wrong file.
