"""Central registry of every detection rule shipped with CloudGuard-IaC.

Rules live in one place — and one place only — so that:

* scanners stay focused on *detection* and never duplicate documentation;
* the ``cloudguard rules`` command, the SARIF export (``driver.rules``) and the
  security-rules table in the README are all generated from the same source;
* adding a rule is a single, reviewable diff.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloudguard.models import Severity

TERRAFORM = "terraform"
DOCKER = "docker"


@dataclass(frozen=True)
class Rule:
    """Static description of a detection rule."""

    id: str
    title: str
    severity: Severity
    category: str
    why: str
    remediation: str
    references: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Serialise the rule to a JSON-compatible dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "why": self.why,
            "remediation": self.remediation,
            "references": list(self.references),
        }


def _rule(
    id: str,
    title: str,
    severity: Severity,
    category: str,
    why: str,
    remediation: str,
    references: tuple[str, ...] = (),
) -> Rule:
    return Rule(
        id=id,
        title=title,
        severity=severity,
        category=category,
        why=why,
        remediation=remediation,
        references=references,
    )


_ALL_RULES: tuple[Rule, ...] = (
    # ------------------------------------------------------------------
    # Terraform / Infrastructure as Code
    # ------------------------------------------------------------------
    _rule(
        "CG_IAC_001",
        "S3 bucket exposed through a public ACL",
        Severity.CRITICAL,
        TERRAFORM,
        "A `public-read` or `public-read-write` ACL makes every object in the bucket "
        "readable — and sometimes writable — by anyone on the Internet. This is the "
        "single most common root cause of cloud data leaks.",
        "Drop the `acl` argument (buckets are private by default since AWS provider v4) "
        "or set it to `private`, and front the bucket with CloudFront + OAC when public "
        "distribution is genuinely required.",
        (
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ),
    ),
    _rule(
        "CG_IAC_002",
        "S3 bucket without a public access block",
        Severity.HIGH,
        TERRAFORM,
        "Without an `aws_s3_bucket_public_access_block` with all four flags enabled, a "
        "future ACL or bucket policy — added by a human or by another module — can "
        "silently make the bucket public.",
        "Declare an `aws_s3_bucket_public_access_block` for the bucket with "
        "`block_public_acls`, `block_public_policy`, `ignore_public_acls` and "
        "`restrict_public_buckets` all set to `true`.",
        (
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        ),
    ),
    _rule(
        "CG_IAC_003",
        "S3 bucket without server-side encryption",
        Severity.HIGH,
        TERRAFORM,
        "Objects stored without server-side encryption are readable by anyone who gets "
        "hold of the underlying storage or a stale backup, and the configuration fails "
        "most compliance baselines (PCI-DSS, HDS, ISO 27001).",
        "Add an `aws_s3_bucket_server_side_encryption_configuration` resource using "
        "`aws:kms` with a customer-managed key, or at minimum `AES256`.",
        ("https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html",),
    ),
    _rule(
        "CG_IAC_004",
        "S3 bucket without versioning",
        Severity.MEDIUM,
        TERRAFORM,
        "Without versioning, an accidental deletion or a ransomware-style overwrite is "
        "irreversible: there is no previous object version to restore.",
        "Add an `aws_s3_bucket_versioning` resource with "
        '`versioning_configuration { status = "Enabled" }`.',
        ("https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html",),
    ),
    _rule(
        "CG_IAC_005",
        "Security group open to the world on an administration port",
        Severity.CRITICAL,
        TERRAFORM,
        "An ingress rule allowing `0.0.0.0/0` on SSH (22), RDP (3389), a database port or "
        "an orchestrator API exposes the instance to permanent Internet-wide credential "
        "stuffing and to any future CVE on that service.",
        "Restrict `cidr_blocks` to your corporate ranges or a bastion security group, and "
        "prefer AWS Systems Manager Session Manager over inbound SSH/RDP altogether.",
        (
            "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
            "https://cwe.mitre.org/data/definitions/284.html",
        ),
    ),
    _rule(
        "CG_IAC_006",
        "Security group ingress open to the world",
        Severity.HIGH,
        TERRAFORM,
        "Ingress from `0.0.0.0/0` (or `::/0`) removes the network layer from your defence "
        "in depth: the application is the only thing left between the Internet and your data.",
        "Scope `cidr_blocks` to known networks, or reference a `source_security_group_id` "
        "so that only peer workloads can reach the port.",
        ("https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",),
    ),
    _rule(
        "CG_IAC_007",
        "Security group allowing every port or every protocol",
        Severity.HIGH,
        TERRAFORM,
        '`protocol = "-1"` or a `0-65535` port range turns the security group into a '
        "no-op: any service accidentally bound on the host becomes reachable.",
        "Declare one ingress rule per port actually needed, with an explicit protocol.",
        ("https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",),
    ),
    _rule(
        "CG_IAC_008",
        "Unencrypted block storage volume",
        Severity.HIGH,
        TERRAFORM,
        "An unencrypted EBS volume or snapshot leaks its full content to anyone able to "
        "attach it, restore it, or read the underlying storage — including a snapshot "
        "shared by mistake.",
        "Set `encrypted = true` and reference a KMS key with `kms_key_id`; enable "
        "EBS encryption by default at the account level.",
        ("https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",),
    ),
    _rule(
        "CG_IAC_009",
        "Unencrypted managed database",
        Severity.HIGH,
        TERRAFORM,
        "An RDS instance or cluster without `storage_encrypted` writes your business data "
        "and its automated backups in clear text. Encryption cannot be enabled in place "
        "later — it requires a full snapshot/restore migration.",
        "Set `storage_encrypted = true` (and `kms_key_id`) at creation time.",
        ("https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",),
    ),
    _rule(
        "CG_IAC_010",
        "Publicly accessible managed database",
        Severity.CRITICAL,
        TERRAFORM,
        "`publicly_accessible = true` gives the database a public IP address. Combined with "
        "a permissive security group it is directly exploitable, and it is a favourite "
        "target of automated scanners.",
        "Set `publicly_accessible = false` and reach the database from private subnets, "
        "through a VPN, a bastion or VPC peering.",
        (
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html",
        ),
    ),
    _rule(
        "CG_IAC_011",
        "Hardcoded secret in Terraform code",
        Severity.CRITICAL,
        TERRAFORM,
        "A password, API key or token written in a `.tf` file is committed to Git forever, "
        "readable by everyone with repository access, and copied into every clone, fork and "
        "CI cache. Rotating it after the fact is the only remedy.",
        "Move the value to a secret manager (AWS Secrets Manager, SSM Parameter Store, Vault) "
        "and inject it via a data source, or use a variable marked `sensitive = true` fed by "
        "the CI secret store.",
        (
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output",
        ),
    ),
    _rule(
        "CG_IAC_012",
        "IAM policy granting wildcard permissions",
        Severity.HIGH,
        TERRAFORM,
        '`Action: "*"` on `Resource: "*"` is an administrator grant. Any compromise of the '
        "attached identity becomes a full account takeover, and it defeats every blast-radius "
        "assumption made elsewhere.",
        "Apply least privilege: enumerate the API actions actually used and scope resources to "
        "explicit ARNs. Use IAM Access Analyzer to generate the policy from CloudTrail history.",
        (
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
            "https://cwe.mitre.org/data/definitions/732.html",
        ),
    ),
    _rule(
        "CG_IAC_013",
        "EC2 instance allowing IMDSv1",
        Severity.MEDIUM,
        TERRAFORM,
        "IMDSv1 answers unauthenticated GET requests, so a single SSRF in the application is "
        "enough to steal the instance role credentials — the exact pattern behind the 2019 "
        "Capital One breach.",
        'Add `metadata_options { http_tokens = "required", http_endpoint = "enabled" }` to '
        "enforce IMDSv2 (session-oriented, PUT-authenticated).",
        (
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        ),
    ),
    _rule(
        "CG_IAC_014",
        "Managed database without backup retention",
        Severity.MEDIUM,
        TERRAFORM,
        "`backup_retention_period = 0` disables automated backups and point-in-time recovery: "
        "a corruption, a bad migration or a ransomware event is unrecoverable.",
        "Set `backup_retention_period` to at least 7 days and test the restore procedure.",
        (
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html",
        ),
    ),
    _rule(
        "CG_IAC_015",
        "S3 bucket without access logging",
        Severity.LOW,
        TERRAFORM,
        "Without server access logs there is no forensic trail: after an incident you cannot "
        "tell which objects were read or by whom.",
        "Add an `aws_s3_bucket_logging` resource pointing at a dedicated log bucket, or enable "
        "CloudTrail data events for the bucket.",
        ("https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",),
    ),
    _rule(
        "CG_IAC_016",
        "Sensitive variable not marked as sensitive",
        Severity.LOW,
        TERRAFORM,
        "A variable named after a secret but without `sensitive = true` is echoed in plan "
        "output, in CI logs and in the state diff, leaking the value to anyone reading the job.",
        "Add `sensitive = true` to the variable declaration.",
        (
            "https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output",
        ),
    ),
    _rule(
        "CG_IAC_017",
        "Unrestricted egress to the Internet",
        Severity.LOW,
        TERRAFORM,
        "Wide-open egress lets a compromised workload exfiltrate data and reach its command "
        "and control server. Egress filtering is what turns a foothold into a dead end.",
        "Restrict egress to the destinations the workload needs, and route the rest through "
        "VPC endpoints or an inspection proxy.",
        ("https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",),
    ),
    # ------------------------------------------------------------------
    # Dockerfile / container images
    # ------------------------------------------------------------------
    _rule(
        "CG_DOCKER_001",
        "Container runs as root",
        Severity.HIGH,
        DOCKER,
        "Without a `USER` instruction the process runs as uid 0. Any RCE in the application "
        "starts with root inside the container, which makes kernel and runtime escapes far "
        "easier and lets the attacker write to mounted volumes.",
        "Create a dedicated unprivileged account (`RUN adduser --system --uid 10001 app`) and "
        "end the final stage with `USER app` (or a numeric uid, required by some "
        "Kubernetes `runAsNonRoot` policies).",
        (
            "https://docs.docker.com/develop/develop-images/instructions/#user",
            "https://cwe.mitre.org/data/definitions/250.html",
        ),
    ),
    _rule(
        "CG_DOCKER_002",
        "Base image not pinned to an immutable tag",
        Severity.MEDIUM,
        DOCKER,
        "`latest` (or no tag at all) means the image you tested is not the image you ship: "
        "builds are irreproducible, a supply-chain compromise of the upstream tag is invisible, "
        "and rollbacks stop being meaningful.",
        "Pin an explicit version and ideally a digest: "
        "`FROM python:3.12-slim@sha256:…`, refreshed by Dependabot or Renovate.",
        ("https://docs.docker.com/build/building/best-practices/#pin-base-image-versions",),
    ),
    _rule(
        "CG_DOCKER_003",
        "Dangerous administration port exposed",
        Severity.HIGH,
        DOCKER,
        "Exposing SSH (22), RDP (3389), Telnet (23) or the Docker daemon socket (2375/2376) "
        "from a container multiplies the attack surface; 2375 in particular is unauthenticated "
        "root-equivalent access to the host.",
        "Remove the `EXPOSE` line and use `docker exec`/`kubectl exec` for debugging. Never "
        "publish the daemon port from inside an image.",
        ("https://docs.docker.com/engine/security/protect-access/",),
    ),
    _rule(
        "CG_DOCKER_004",
        "Remote script piped into a shell",
        Severity.HIGH,
        DOCKER,
        "`curl … | sh` executes whatever the server returns at build time, with no signature "
        "and no integrity check. A compromised — or simply hijacked — URL means arbitrary code "
        "baked into your image.",
        "Download to a file, verify a checksum or a signature, then execute. Better: install "
        "from the distribution package manager or a pinned release artefact.",
        ("https://cwe.mitre.org/data/definitions/494.html",),
    ),
    _rule(
        "CG_DOCKER_005",
        "Secret baked into the image",
        Severity.CRITICAL,
        DOCKER,
        "`ENV`/`ARG` values are stored in the image metadata and readable with "
        "`docker history` by anyone who can pull the image — including from a public registry. "
        "Deleting the secret in a later layer does not remove it.",
        "Inject secrets at runtime (environment injected by the orchestrator, mounted file) or "
        "at build time with BuildKit secret mounts: "
        "`RUN --mount=type=secret,id=token …`.",
        (
            "https://docs.docker.com/build/building/secrets/",
            "https://cwe.mitre.org/data/definitions/522.html",
        ),
    ),
    _rule(
        "CG_DOCKER_006",
        "ADD used with a remote URL",
        Severity.MEDIUM,
        DOCKER,
        "`ADD http://…` fetches an unverified remote artefact and silently auto-extracts "
        "archives, which has historically enabled path-traversal (zip-slip) style attacks.",
        'Use `COPY` for local files, and `RUN curl -fsSL … && echo "<sha256>  file" | '
        "sha256sum -c -` when a download is unavoidable.",
        ("https://docs.docker.com/build/building/best-practices/#add-or-copy",),
    ),
    _rule(
        "CG_DOCKER_007",
        "Privilege escalation tooling installed",
        Severity.MEDIUM,
        DOCKER,
        "Shipping `sudo` — or worse, a passwordless sudoers entry — inside an image gives any "
        "code execution a ready-made path back to root, defeating the `USER` directive.",
        "Do the privileged work in build stages that run as root, then drop to an unprivileged "
        "`USER` for the runtime stage. Do not install `sudo`.",
        ("https://docs.docker.com/develop/develop-images/instructions/#user",),
    ),
    _rule(
        "CG_DOCKER_008",
        "World-writable permissions applied",
        Severity.MEDIUM,
        DOCKER,
        "`chmod 777` (or `chmod -R 777`) lets any process in the container — including a "
        "compromised low-privilege one — rewrite application code and binaries, turning a read "
        "primitive into persistence.",
        "Grant the minimum required mode (`chmod 750`, `chmod 640`) and set ownership with "
        "`COPY --chown=app:app`.",
        ("https://cwe.mitre.org/data/definitions/732.html",),
    ),
    _rule(
        "CG_DOCKER_009",
        "Package installed without version pinning",
        Severity.LOW,
        DOCKER,
        "Unpinned `pip install`/`npm install` resolves to whatever version exists at build "
        "time: builds drift, and a malicious release published upstream lands straight in your "
        "image.",
        "Pin versions and hashes: `pip install -r requirements.txt --require-hashes`, "
        "`npm ci` with a committed lockfile.",
        ("https://cwe.mitre.org/data/definitions/1357.html",),
    ),
    _rule(
        "CG_DOCKER_010",
        "Package manager cache left in the image",
        Severity.LOW,
        DOCKER,
        "Leftover apt/apk indexes and recommended packages inflate the image and ship extra "
        "binaries that show up as CVEs and give an attacker more tools to work with.",
        "Chain `apt-get install --no-install-recommends` with "
        "`rm -rf /var/lib/apt/lists/*` in the same `RUN`, or use `apk add --no-cache`.",
        ("https://docs.docker.com/build/building/best-practices/#apt-get",),
    ),
    _rule(
        "CG_DOCKER_011",
        "Missing HEALTHCHECK instruction",
        Severity.LOW,
        DOCKER,
        "Without a health check the orchestrator cannot tell a hung or half-compromised "
        "container from a healthy one, so a failing workload keeps receiving traffic.",
        "Add a lightweight `HEALTHCHECK CMD` probing a real endpoint, with sensible "
        "`--interval` and `--timeout` values.",
        ("https://docs.docker.com/reference/dockerfile/#healthcheck",),
    ),
    _rule(
        "CG_DOCKER_012",
        "Whole build context copied into the image",
        Severity.MEDIUM,
        DOCKER,
        "`COPY . .` ships everything the build context contains — `.git`, `.env`, private keys, "
        "CI configuration — unless a `.dockerignore` excludes it. Secrets leak into layers this "
        "way constantly.",
        "Copy only what the runtime needs (`COPY src/ ./src/`) and always commit a "
        "`.dockerignore` covering `.git`, `.env`, `*.pem` and local tooling.",
        ("https://docs.docker.com/build/building/context/#dockerignore-files",),
    ),
    _rule(
        "CG_DOCKER_013",
        "Deprecated or superseded instruction",
        Severity.INFO,
        DOCKER,
        "`MAINTAINER` has been deprecated since Docker 1.13; it is not read by modern tooling, "
        "so ownership information is lost when it matters (during an incident).",
        "Replace it with an OCI label: "
        '`LABEL org.opencontainers.image.authors="team@example.com"`.',
        ("https://github.com/opencontainers/image-spec/blob/main/annotations.md",),
    ),
    _rule(
        "CG_DOCKER_014",
        "Blanket distribution upgrade at build time",
        Severity.LOW,
        DOCKER,
        "`apt-get upgrade`/`dist-upgrade` inside a build makes the image content depend on the "
        "build date, so two builds of the same commit produce different — and differently "
        "vulnerable — images.",
        "Rebuild on a freshly patched, pinned base image instead of upgrading in place, and "
        "let Dependabot/Renovate bump the base tag.",
        ("https://docs.docker.com/build/building/best-practices/#apt-get",),
    ),
)

#: All rules, keyed by identifier.
RULES: dict[str, Rule] = {rule.id: rule for rule in _ALL_RULES}


def get_rule(rule_id: str) -> Rule:
    """Return the rule with the given id.

    Raises:
        KeyError: if ``rule_id`` is unknown — a bug in a scanner, caught by the
            registry consistency test.
    """
    return RULES[rule_id]


def all_rules(category: str | None = None, min_severity: Severity | None = None) -> list[Rule]:
    """Return the rules matching the given filters, ordered by id."""
    rules = sorted(RULES.values(), key=lambda r: r.id)
    if category:
        rules = [r for r in rules if r.category == category]
    if min_severity is not None:
        rules = [r for r in rules if r.severity >= min_severity]
    return rules
