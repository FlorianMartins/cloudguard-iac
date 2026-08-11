# =============================================================================
# CloudGuard-IaC — container image of the scanner itself.
#
# This image is scanned by CloudGuard on every commit (see the `dogfood` job in
# .github/workflows/ci-cd.yml): the tool has to pass its own Docker rules.
#
#   docker build -t cloudguard-iac .
#   docker run --rm -v "$PWD:/scan:ro" cloudguard-iac full-scan /scan
# =============================================================================

# Pin the digest in production — `python:3.12-slim-bookworm@sha256:<digest>` —
# and let Renovate keep it fresh.
FROM python:3.14-slim-bookworm AS builder

WORKDIR /src

# Only what the build backend needs, so the layer is cached across code changes.
COPY pyproject.toml README.md ./
COPY cloudguard/ ./cloudguard/

RUN pip install --no-cache-dir --prefix=/install .

# -----------------------------------------------------------------------------
# Runtime — no build tooling, no shell utilities, no root
# -----------------------------------------------------------------------------
# CloudGuard's own CG_DOCKER_011 asks for a HEALTHCHECK. This image runs a
# one-shot CLI and exits: there is no long-running process to probe, so the rule
# is suppressed here with an explicit justification rather than silenced globally.
# cloudguard:ignore CG_DOCKER_011 one-shot CLI image, nothing to health-check
FROM python:3.14-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="cloudguard-iac" \
      org.opencontainers.image.description="Shift-left security scanner for Terraform and container images" \
      org.opencontainers.image.source="https://github.com/FlorianMartins/cloudguard-iac" \
      org.opencontainers.image.licenses="MIT"

RUN groupadd --system --gid 10001 cloudguard \
    && useradd --system --uid 10001 --gid cloudguard \
       --home /home/cloudguard --create-home --shell /usr/sbin/nologin cloudguard

COPY --from=builder /install /usr/local

USER 10001:10001

# Mount the code to analyse read-only on /scan.
WORKDIR /scan

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["cloudguard"]
CMD ["--help"]
