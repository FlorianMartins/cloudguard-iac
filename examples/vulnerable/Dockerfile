# =============================================================================
# ⚠️  VULNERABLE BY DESIGN — DO NOT BUILD OR PUBLISH  ⚠️
#
# Reference image for CloudGuard-IaC's Docker rules. The hardened version of the
# same application lives in ../secure/Dockerfile.
# =============================================================================

# CG_DOCKER_002 — unpinned base image: what you tested is not what you ship.
FROM ubuntu:latest

# CG_DOCKER_013 — deprecated instruction.
MAINTAINER devops@acme.example

# CG_DOCKER_005 — credentials baked into the image layers, readable with
# `docker history` by anyone who can pull the image.
ENV DB_PASSWORD=P@ssw0rd-production-2024
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ARG GITHUB_TOKEN=ghp_R2d2C3po00000000000000000000000000

# CG_DOCKER_010 — no --no-install-recommends, apt lists left behind.
# CG_DOCKER_014 — blanket upgrade makes the build non-reproducible.
# CG_DOCKER_007 — sudo shipped inside the image.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y python3 python3-pip curl sudo openssh-server

# CG_DOCKER_004 — remote script piped straight into a shell, no signature check.
RUN curl -fsSL https://get.example.com/install.sh | bash

# CG_DOCKER_006 — remote artefact fetched with no integrity verification.
ADD https://releases.example.com/agent/latest/agent.tar.gz /opt/agent.tar.gz

# CG_DOCKER_009 — unpinned dependencies: any upstream release lands in the image.
RUN pip3 install flask requests boto3

WORKDIR /app

# CG_DOCKER_012 — the whole build context (.git, .env, keys…) ends up in a layer.
COPY . .

# CG_DOCKER_008 — world-writable application directory.
RUN chmod -R 777 /app

# CG_DOCKER_003 — SSH inside a container: an entire extra attack surface.
EXPOSE 22
EXPOSE 8080

# CG_DOCKER_001 — no USER: the process runs as root (uid 0).
# CG_DOCKER_011 — no HEALTHCHECK: the orchestrator cannot tell healthy from hung.
CMD ["python3", "/app/server.py"]
