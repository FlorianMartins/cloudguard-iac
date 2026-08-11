"""Terraform scanner — structural analysis of ``.tf`` files.

Every check walks the syntax tree produced by :mod:`cloudguard.scanners.hcl`
rather than the raw text, which is what makes the difference between "the file
mentions 0.0.0.0/0 somewhere" and "this *ingress* rule opens port 22 to the
Internet".

Some Terraform properties are not expressed on the resource itself: since AWS
provider v4, a bucket's encryption, versioning, logging and public-access block
are *separate resources* that reference it. The scanner therefore builds a
module-wide index first (:class:`_ModuleIndex`) so a bucket declared in
``s3.tf`` can be validated against a companion declared in ``main.tf``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudguard.models import Finding, Severity
from cloudguard.scanners.base import SENSITIVE_NAME_TOKENS, BaseScanner
from cloudguard.scanners.hcl import Block, HCLParseError, Value, parse_hcl

#: ACLs that expose bucket content beyond the account.
PUBLIC_ACLS: frozenset[str] = frozenset(
    {"public-read", "public-read-write", "website", "authenticated-read"}
)

#: Ports whose exposure to the Internet is critical on its own.
ADMIN_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    135: "MSRPC",
    137: "NetBIOS",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker daemon (plaintext)",
    2376: "Docker daemon",
    2379: "etcd",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6443: "Kubernetes API",
    8020: "HDFS NameNode",
    9200: "Elasticsearch",
    9300: "Elasticsearch transport",
    11211: "Memcached",
    27017: "MongoDB",
}

#: CIDRs meaning "the whole Internet".
WORLD_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0", "0.0.0.0/0,::/0"})

#: Resource types carrying an inline IAM policy document.
IAM_POLICY_RESOURCES: frozenset[str] = frozenset(
    {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
        "aws_s3_bucket_policy",
        "aws_sqs_queue_policy",
        "aws_sns_topic_policy",
    }
)

#: Attribute name suffixes that look sensitive but never hold a secret.
_SECRET_NAME_EXCEPTIONS: tuple[str, ...] = (
    "_arn",
    "_id",
    "_ids",
    "_name",
    "_names",
    "_path",
    "_file",
    "_length",
    "_enabled",
    "_version",
    "_algorithm",
    "_days",
    "_policy",
    "_rotation",
    "_type",
    "_count",
    "_url",
    "_field",
    "_key_ref",
)

#: Attribute names that contain a sensitive word but never hold a credential.
#: ``http_tokens = "required"`` (IMDSv2) is the canonical example.
_SECRET_NAME_ALLOWLIST: frozenset[str] = frozenset(
    {
        "http_tokens",
        "token_url",
        "token_endpoint",
        "password_policy",
        "password_length",
        "password_reuse_prevention",
        "require_password_change",
        "secret_string_key",
        "secrets_manager_arn",
        "credentials_mode",
        "manage_master_user_password",
        "master_user_secret_kms_key_id",
        "rotate_secret",
    }
)

#: Values that are references or ARNs rather than literal secrets.
_SECRET_VALUE_PREFIXES: tuple[str, ...] = ("arn:", "http://", "https://", "/", "./", "../")

#: Well-known credential shapes worth flagging wherever they appear.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("an AWS access key id", re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("a private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("a GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("a Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
)


@dataclass
class _ParsedFile:
    """A parsed Terraform file kept together with its source."""

    path: str
    text: str
    body: Block


@dataclass
class _ModuleIndex:
    """Cross-file view of the resources declared in a scan target."""

    by_type: dict[str, list[Block]] = field(default_factory=dict)

    @classmethod
    def build(cls, files: list[_ParsedFile]) -> _ModuleIndex:
        """Index every ``resource`` block of the module by resource type."""
        index = cls()
        for parsed in files:
            for block in parsed.body.resources():
                index.by_type.setdefault(block.resource_type, []).append(block)
        return index

    def companions(
        self, resource_type: str, target: str, *, attribute: str = "bucket"
    ) -> list[Block]:
        """Return resources of ``resource_type`` attached to ``target``.

        The link is matched on a single attribute — ``bucket`` for the S3
        companion resources — because matching *any* attribute would confuse
        attachment with mere mention: an ``aws_s3_bucket_logging`` naming a log
        bucket in ``target_bucket`` does not give that log bucket its own
        logging. The reference itself may be written as ``.id``, ``.bucket``,
        ``.arn`` or interpolated.
        """
        matches: list[Block] = []
        for block in self.by_type.get(resource_type, []):
            value = block.get(attribute)
            if value is not None and _mentions(value.raw, target):
                matches.append(block)
        return matches


def _mentions(expression: str, address: str) -> bool:
    """``True`` when an expression references the given resource address."""
    return re.search(rf"(?<![\w.]){re.escape(address)}(?![\w])", expression) is not None


def _to_python(value: Value | None) -> Any:
    """Convert a parsed value into plain Python data (``None`` when unknown)."""
    if value is None:
        return None
    literal = value.literal
    if isinstance(literal, list):
        return [_to_python(item) for item in literal]
    if isinstance(literal, dict):
        return {key: _to_python(item) for key, item in literal.items()}
    return literal


def _as_list(value: Any) -> list[Any]:
    """Normalise a JSON field that may be a scalar or a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class IaCScanner(BaseScanner):
    """Detect misconfigurations in Terraform code."""

    name = "terraform"
    category = "terraform"

    #: Files this scanner claims.
    suffixes: tuple[str, ...] = (".tf",)

    def __init__(self) -> None:
        super().__init__()
        self.errors: list[str] = []

    def matches(self, path: Path) -> bool:
        """``True`` for ``.tf`` files (``.tfvars`` are handled by the secret rules)."""
        return path.suffix in self.suffixes or path.name.endswith(".tfvars")

    # -- entry points --------------------------------------------------------

    def analyse(self, text: str, display_path: str) -> list[Finding]:
        """Analyse a single Terraform file."""
        return self.analyse_files({display_path: text})

    def analyse_files(self, sources: dict[str, str]) -> list[Finding]:
        """Analyse a whole module so cross-resource rules can see every file."""
        self.errors = []
        parsed_files: list[_ParsedFile] = []
        for path, text in sources.items():
            try:
                body = parse_hcl(text)
            except HCLParseError as exc:
                self.errors.append(f"{path}: {exc}")
                continue
            parsed_files.append(_ParsedFile(path=path, text=text, body=body))

        index = _ModuleIndex.build(parsed_files)
        findings: list[Finding] = []
        for parsed in parsed_files:
            self.set_source(parsed.text, parsed.path)
            findings.extend(self._scan_file(parsed, index))
        return findings

    # -- dispatch ------------------------------------------------------------

    def _scan_file(self, parsed: _ParsedFile, index: _ModuleIndex) -> list[Finding]:
        findings: list[Finding] = []
        for block in parsed.body.blocks:
            if block.type == "resource":
                findings.extend(self._scan_resource(block, index))
            elif block.type == "data":
                findings.extend(self._check_iam_policy_document(block))
            elif block.type == "variable":
                findings.extend(self._check_variable(block))
        findings.extend(self._check_secrets(parsed.body))
        return findings

    def _scan_resource(self, block: Block, index: _ModuleIndex) -> list[Finding]:
        resource_type = block.resource_type
        findings: list[Finding] = []

        if resource_type == "aws_s3_bucket":
            findings.extend(self._check_s3_bucket(block, index))
        elif resource_type == "aws_s3_bucket_acl":
            findings.extend(self._check_s3_bucket_acl(block))
        elif resource_type in ("aws_security_group", "aws_default_security_group"):
            findings.extend(self._check_security_group(block))
        elif resource_type == "aws_security_group_rule":
            findings.extend(self._check_security_group_rule(block))
        elif resource_type in (
            "aws_vpc_security_group_ingress_rule",
            "aws_vpc_security_group_egress_rule",
        ):
            findings.extend(self._check_vpc_security_group_rule(block))
        elif resource_type == "aws_ebs_volume":
            findings.extend(self._check_encrypted_flag(block, "encrypted", "EBS volume"))
        elif resource_type == "aws_efs_file_system":
            findings.extend(self._check_encrypted_flag(block, "encrypted", "EFS file system"))
        elif resource_type == "aws_instance":
            findings.extend(self._check_instance(block))
        elif resource_type in ("aws_db_instance", "aws_rds_cluster"):
            findings.extend(self._check_database(block))
        elif resource_type in ("aws_redshift_cluster", "aws_dms_replication_instance"):
            findings.extend(self._check_public_flag(block))

        if resource_type in IAM_POLICY_RESOURCES:
            findings.extend(self._check_iam_policy(block))

        return findings

    # -- S3 ------------------------------------------------------------------

    def _check_s3_bucket(self, block: Block, index: _ModuleIndex) -> list[Finding]:
        findings: list[Finding] = []
        address = block.address

        acl = block.get("acl")
        acl_value = acl.as_str() if acl else None
        if acl and acl_value in PUBLIC_ACLS:
            findings.append(
                self.finding(
                    "CG_IAC_001",
                    line=acl.line,
                    resource=address,
                    message=f'bucket ACL is "{acl_value}", which grants access outside the account',
                )
            )

        blocker = self._effective_public_access_block(index, address)
        if blocker is None:
            findings.append(
                self.finding(
                    "CG_IAC_002",
                    line=block.line,
                    resource=address,
                    message="no aws_s3_bucket_public_access_block protects this bucket",
                )
            )
        else:
            missing = [flag for flag, enabled in blocker.items() if not enabled]
            if missing:
                findings.append(
                    self.finding(
                        "CG_IAC_002",
                        line=block.line,
                        resource=address,
                        message=(
                            "public access block leaves " + ", ".join(sorted(missing)) + " disabled"
                        ),
                    )
                )

        if not self._has_encryption(block, index, address):
            findings.append(
                self.finding(
                    "CG_IAC_003",
                    line=block.line,
                    resource=address,
                    message="no server-side encryption configured for this bucket",
                )
            )

        if not self._has_versioning(block, index, address):
            findings.append(
                self.finding(
                    "CG_IAC_004",
                    line=block.line,
                    resource=address,
                    message="versioning is not enabled on this bucket",
                )
            )

        if not (block.get_blocks("logging") or index.companions("aws_s3_bucket_logging", address)):
            findings.append(
                self.finding(
                    "CG_IAC_015",
                    line=block.line,
                    resource=address,
                    message="no server access logging configured for this bucket",
                )
            )

        return findings

    @staticmethod
    def _effective_public_access_block(index: _ModuleIndex, address: str) -> dict[str, bool] | None:
        """Return the four public-access flags, or ``None`` when no block exists."""
        companions = index.companions("aws_s3_bucket_public_access_block", address)
        if not companions:
            return None
        flags = {
            "block_public_acls": False,
            "block_public_policy": False,
            "ignore_public_acls": False,
            "restrict_public_buckets": False,
        }
        for companion in companions:
            for flag in flags:
                if companion.get_bool(flag) is True:
                    flags[flag] = True
        return flags

    def _has_encryption(self, block: Block, index: _ModuleIndex, address: str) -> bool:
        if block.get_blocks("server_side_encryption_configuration"):
            return True
        return bool(index.companions("aws_s3_bucket_server_side_encryption_configuration", address))

    def _has_versioning(self, block: Block, index: _ModuleIndex, address: str) -> bool:
        for inline in block.get_blocks("versioning"):
            if inline.get_bool("enabled") is True:
                return True
        for companion in index.companions("aws_s3_bucket_versioning", address):
            for config in companion.get_blocks("versioning_configuration"):
                if (config.get_str("status") or "").lower() == "enabled":
                    return True
        return False

    def _check_s3_bucket_acl(self, block: Block) -> list[Finding]:
        acl = block.get("acl")
        if acl and acl.as_str() in PUBLIC_ACLS:
            return [
                self.finding(
                    "CG_IAC_001",
                    line=acl.line,
                    resource=block.address,
                    message=(
                        f'bucket ACL is "{acl.as_str()}", which grants access outside the account'
                    ),
                )
            ]
        return []

    # -- network -------------------------------------------------------------

    def _check_security_group(self, block: Block) -> list[Finding]:
        findings: list[Finding] = []
        for ingress in block.get_blocks("ingress"):
            findings.extend(self._check_ingress(ingress, block.address, ingress.line))
        for egress in block.get_blocks("egress"):
            findings.extend(self._check_egress(egress, block.address, egress.line))
        return findings

    def _check_security_group_rule(self, block: Block) -> list[Finding]:
        rule_type = (block.get_str("type") or "ingress").lower()
        if rule_type == "egress":
            return self._check_egress(block, block.address, block.line)
        return self._check_ingress(block, block.address, block.line)

    def _check_vpc_security_group_rule(self, block: Block) -> list[Finding]:
        if block.resource_type.endswith("egress_rule"):
            return self._check_egress(block, block.address, block.line)
        return self._check_ingress(block, block.address, block.line)

    @staticmethod
    def _rule_cidrs(block: Block) -> list[str]:
        cidrs: list[str] = []
        for attribute in ("cidr_blocks", "ipv6_cidr_blocks"):
            value = block.get(attribute)
            if value:
                cidrs.extend(value.str_items())
        for attribute in ("cidr_ipv4", "cidr_ipv6"):
            single = block.get_str(attribute)
            if single:
                cidrs.append(single)
        return cidrs

    @staticmethod
    def _rule_protocol(block: Block) -> str:
        value = block.get("protocol") or block.get("ip_protocol")
        if value is None:
            return ""
        if value.as_str() is not None:
            return str(value.as_str()).lower()
        number = value.as_int()
        return str(number) if number is not None else ""

    @staticmethod
    def _rule_ports(block: Block) -> tuple[int | None, int | None]:
        return block.get_int("from_port"), block.get_int("to_port")

    def _check_ingress(self, block: Block, address: str, line: int) -> list[Finding]:
        cidrs = self._rule_cidrs(block)
        open_to_world = any(cidr in WORLD_CIDRS for cidr in cidrs)
        protocol = self._rule_protocol(block)
        from_port, to_port = self._rule_ports(block)
        all_protocols = protocol in ("-1", "all")
        all_ports = all_protocols or (from_port == 0 and to_port == 65535)

        if all_ports:
            scope = "to the whole Internet (0.0.0.0/0)" if open_to_world else "to its source range"
            detail = (
                'protocol is "-1" (every protocol)'
                if all_protocols
                else "port range covers 0-65535"
            )
            return [
                self.finding(
                    "CG_IAC_007",
                    line=line,
                    resource=address,
                    message=f"ingress {detail} and is open {scope}",
                    severity=Severity.CRITICAL if open_to_world else Severity.HIGH,
                )
            ]

        if not open_to_world:
            return []

        exposed = self._exposed_admin_ports(from_port, to_port)
        if exposed:
            names = ", ".join(f"{port}/{name}" for port, name in exposed)
            return [
                self.finding(
                    "CG_IAC_005",
                    line=line,
                    resource=address,
                    message=f"ingress from 0.0.0.0/0 reaches {names}",
                )
            ]

        port_label = _format_ports(from_port, to_port)
        return [
            self.finding(
                "CG_IAC_006",
                line=line,
                resource=address,
                message=f"ingress on {port_label} is open to 0.0.0.0/0",
            )
        ]

    def _check_egress(self, block: Block, address: str, line: int) -> list[Finding]:
        cidrs = self._rule_cidrs(block)
        if not any(cidr in WORLD_CIDRS for cidr in cidrs):
            return []
        return [
            self.finding(
                "CG_IAC_017",
                line=line,
                resource=address,
                message="egress allows every destination on the Internet (0.0.0.0/0)",
            )
        ]

    @staticmethod
    def _exposed_admin_ports(from_port: int | None, to_port: int | None) -> list[tuple[int, str]]:
        """Administration ports covered by a port range (empty when unknown)."""
        if from_port is None or to_port is None:
            return []
        low, high = min(from_port, to_port), max(from_port, to_port)
        return [(port, name) for port, name in sorted(ADMIN_PORTS.items()) if low <= port <= high]

    # -- storage and compute -------------------------------------------------

    def _check_encrypted_flag(self, block: Block, attribute: str, label: str) -> list[Finding]:
        value = block.get(attribute)
        if value is not None and value.as_bool() is True:
            return []
        line = value.line if value else block.line
        state = "set to false" if value is not None else "not set"
        return [
            self.finding(
                "CG_IAC_008",
                line=line,
                resource=block.address,
                message=f"{label} has encryption {state}",
            )
        ]

    def _check_instance(self, block: Block) -> list[Finding]:
        findings: list[Finding] = []

        for device in block.get_blocks("root_block_device", "ebs_block_device"):
            if device.get_bool("encrypted") is not True:
                findings.append(
                    self.finding(
                        "CG_IAC_008",
                        line=device.line,
                        resource=block.address,
                        message=f"{device.type} is not encrypted",
                    )
                )

        metadata = block.get_blocks("metadata_options")
        tokens = ""
        for options in metadata:
            tokens = (options.get_str("http_tokens") or "").lower()
        if not metadata:
            findings.append(
                self.finding(
                    "CG_IAC_013",
                    line=block.line,
                    resource=block.address,
                    message="no metadata_options block: IMDSv1 stays available",
                )
            )
        elif tokens != "required":
            findings.append(
                self.finding(
                    "CG_IAC_013",
                    line=metadata[0].line,
                    resource=block.address,
                    message=f'http_tokens is "{tokens or "optional"}" instead of "required"',
                )
            )

        return findings

    def _check_database(self, block: Block) -> list[Finding]:
        findings: list[Finding] = []
        address = block.address

        encrypted = block.get("storage_encrypted")
        if encrypted is None or encrypted.as_bool() is not True:
            findings.append(
                self.finding(
                    "CG_IAC_009",
                    line=encrypted.line if encrypted else block.line,
                    resource=address,
                    message="storage_encrypted is not enabled on this database",
                )
            )

        findings.extend(self._check_public_flag(block))

        retention = block.get("backup_retention_period")
        retention_value = retention.as_int() if retention else None
        if retention is None:
            findings.append(
                self.finding(
                    "CG_IAC_014",
                    line=block.line,
                    resource=address,
                    message="backup_retention_period is not set (automated backups disabled)",
                )
            )
        elif retention_value is not None and retention_value < 7:
            findings.append(
                self.finding(
                    "CG_IAC_014",
                    line=retention.line,
                    resource=address,
                    message=(
                        f"backup_retention_period is {retention_value} day(s), "
                        "below the 7-day baseline"
                    ),
                )
            )

        return findings

    def _check_public_flag(self, block: Block) -> list[Finding]:
        public = block.get("publicly_accessible")
        if public is not None and public.as_bool() is True:
            return [
                self.finding(
                    "CG_IAC_010",
                    line=public.line,
                    resource=block.address,
                    message="publicly_accessible is true: the endpoint gets a public IP",
                )
            ]
        return []

    # -- IAM -----------------------------------------------------------------

    def _check_iam_policy(self, block: Block) -> list[Finding]:
        findings: list[Finding] = []
        for attribute in ("policy", "assume_role_policy"):
            value = block.get(attribute)
            if value is None:
                continue
            document = self._policy_document(value)
            if not document:
                continue
            if self._grants_wildcard(document):
                findings.append(
                    self.finding(
                        "CG_IAC_012",
                        line=value.line,
                        resource=block.address,
                        message=f'{attribute} allows Action "*" on Resource "*"',
                    )
                )
        return findings

    @staticmethod
    def _policy_document(value: Value) -> dict[str, Any] | None:
        """Resolve a policy attribute written as ``jsonencode(...)`` or raw JSON."""
        encoded = value.unwrap_call("jsonencode")
        if encoded is not None:
            document = _to_python(encoded)
            return document if isinstance(document, dict) else None

        text = value.as_str()
        if text:
            try:
                document = json.loads(text)
            except (ValueError, TypeError):
                return None
            return document if isinstance(document, dict) else None

        document = _to_python(value)
        return document if isinstance(document, dict) else None

    @staticmethod
    def _grants_wildcard(document: dict[str, Any]) -> bool:
        for statement in _as_list(document.get("Statement")):
            if not isinstance(statement, dict):
                continue
            if str(statement.get("Effect", "Allow")).lower() != "allow":
                continue
            actions = [str(a) for a in _as_list(statement.get("Action")) if a is not None]
            resources = [str(r) for r in _as_list(statement.get("Resource")) if r is not None]
            if "*" in actions and (not resources or "*" in resources):
                return True
        return False

    def _check_iam_policy_document(self, block: Block) -> list[Finding]:
        """Handle ``data "aws_iam_policy_document"`` blocks."""
        if block.resource_type != "aws_iam_policy_document":
            return []
        findings: list[Finding] = []
        for statement in block.get_blocks("statement"):
            effect = (statement.get_str("effect") or "Allow").lower()
            if effect != "allow":
                continue
            actions = statement.get("actions")
            resources = statement.get("resources")
            action_items = actions.str_items() if actions else []
            resource_items = resources.str_items() if resources else []
            if "*" in action_items and "*" in resource_items:
                findings.append(
                    self.finding(
                        "CG_IAC_012",
                        line=statement.line,
                        resource=block.address,
                        message='statement allows Action "*" on Resource "*"',
                    )
                )
        return findings

    # -- secrets -------------------------------------------------------------

    def _check_variable(self, block: Block) -> list[Finding]:
        findings: list[Finding] = []
        name = block.name.lower()
        if not any(token in name for token in SENSITIVE_NAME_TOKENS):
            return findings

        if block.get_bool("sensitive") is not True:
            findings.append(
                self.finding(
                    "CG_IAC_016",
                    line=block.line,
                    resource=f"variable.{block.name}",
                    message=f'variable "{block.name}" holds a secret but is not marked sensitive',
                )
            )

        default = block.get("default")
        if default is not None and _is_secret_literal(default.as_str()):
            findings.append(
                self.finding(
                    "CG_IAC_011",
                    line=default.line,
                    resource=f"variable.{block.name}",
                    message=f'variable "{block.name}" has a hardcoded default secret',
                )
            )
        return findings

    def _check_secrets(self, body: Block) -> list[Finding]:
        """Flag literal credentials anywhere in the file."""
        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()

        for block in body.walk():
            if block.type == "variable":
                continue  # handled by _check_variable, avoids duplicate reports
            address = block.address if block.type != "__root__" else "(root)"
            for attribute, value in block.attributes.items():
                text = value.as_str()
                if text is None:
                    continue

                key = (value.line, "CG_IAC_011")
                lowered = attribute.lower()
                if (
                    any(token in lowered for token in SENSITIVE_NAME_TOKENS)
                    and lowered not in _SECRET_NAME_ALLOWLIST
                    and not lowered.endswith(_SECRET_NAME_EXCEPTIONS)
                    and _is_secret_literal(text)
                    and key not in seen
                ):
                    seen.add(key)
                    findings.append(
                        self.finding(
                            "CG_IAC_011",
                            line=value.line,
                            resource=address,
                            message=f'"{attribute}" is set to a literal secret value',
                        )
                    )
                    continue

                for label, pattern in _SECRET_PATTERNS:
                    match = pattern.search(text)
                    if not match:
                        continue
                    line = value.line + text[: match.start()].count("\n")
                    key = (line, "CG_IAC_011")
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.finding(
                            "CG_IAC_011",
                            line=line,
                            resource=address,
                            message=f'"{attribute}" contains {label}',
                        )
                    )
                    break

        return findings


def _is_secret_literal(text: str | None) -> bool:
    """``True`` when a literal string looks like a real credential."""
    if not text or len(text) < 4:
        return False
    if text.startswith(_SECRET_VALUE_PREFIXES):
        return False
    return not ("${" in text or text.strip().startswith(("var.", "local.", "data.")))


def _format_ports(from_port: int | None, to_port: int | None) -> str:
    """Human readable port range."""
    if from_port is None and to_port is None:
        return "an unspecified port range"
    if from_port == to_port or to_port is None:
        return f"port {from_port}"
    return f"ports {from_port}-{to_port}"
