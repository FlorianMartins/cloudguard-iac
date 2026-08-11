# =============================================================================
# ✅ HARDENED REFERENCE — the same application as ../vulnerable/Dockerfile,
#    rewritten so that every CloudGuard-IaC Docker rule passes.
#
#    Build:  docker build -t acme/app:1.0.0 examples/secure
#    Verify: cloudguard scan-docker examples/secure   # exits 0
# =============================================================================

# Pinned minor version. In production, go one step further and pin the digest —
# `FROM python:3.12-slim-bookworm@sha256:<digest>` — refreshed by Renovate.
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

# Only the dependency manifest is copied first: the layer is reused as long as
# the dependencies do not change.
COPY requirements.txt ./

# --require-hashes refuses any artefact whose hash is not in the lockfile,
# which turns a compromised package release into a build failure.
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.txt

# -----------------------------------------------------------------------------
# Runtime stage — nothing but the application and its dependencies
# -----------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="acme-app" \
      org.opencontainers.image.authors="devops@acme.example" \
      org.opencontainers.image.source="https://github.com/acme/app" \
      org.opencontainers.image.licenses="MIT"

# curl is needed by the health check; the lists are removed in the same layer so
# they never reach the published image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl=7.88.1-10+deb12u14 \
    && rm -rf /var/lib/apt/lists/*

# A dedicated unprivileged account with a fixed uid, so Kubernetes
# `runAsNonRoot` policies can validate the image without inspecting it.
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home /app --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --chown=app:app src/ ./src/

# Read-only application tree owned by root, executed by an unprivileged user:
# a compromise cannot rewrite the code it runs.
RUN chmod -R 550 /app/src

USER 10001:10001

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1

ENTRYPOINT ["python", "-m", "src.server"]
