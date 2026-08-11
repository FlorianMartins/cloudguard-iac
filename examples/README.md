# Example corpus

Two mirrored deployments of the same fictional application, used as documentation, as a
demonstration and as the regression net of the test suite.

| | `vulnerable/` | `secure/` |
|---|---|---|
| Purpose | Trigger **every** rule of the catalogue | Pass **every** rule of the catalogue |
| Expected result | 37 findings, exit code `1` | 0 findings, exit code `0` |

```bash
cloudguard full-scan examples/vulnerable   # blocks — this is the point
cloudguard full-scan examples/secure       # clean
diff -u examples/vulnerable/main.tf examples/secure/main.tf
```

## ⚠️ Do not deploy `vulnerable/`

These files describe a public bucket, an SSH port open to the Internet, an unencrypted and
publicly reachable database, an administrator IAM policy and credentials in clear text.
They exist to be detected, never to be applied. The credentials they contain are the
public AWS documentation examples (`AKIAIOSFODNN7EXAMPLE`), not real secrets.

## `secure/` is a reference, not a runnable app

The hardened `Dockerfile` refers to a `requirements.txt` and a `src/` directory that are
not shipped here: the file documents the build practices (multi-stage, pinned base image,
hashed dependencies, unprivileged uid, health check), it is not meant to be built as is.

## Keeping them in sync

`tests/test_examples.py` asserts that every one of the 31 rules fires on `vulnerable/` and
that none fires on `secure/`. Adding a rule therefore means adding the vulnerable pattern
**and** its fix — which is exactly how the corpus stays honest.

One suppression lives in `secure/main.tf`: the log destination bucket cannot log into
itself without creating an object loop, so `CG_IAC_015` is waived there with a written
justification — an example of the accepted-risk workflow.
