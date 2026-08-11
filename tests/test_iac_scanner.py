"""Rule-by-rule tests for the Terraform scanner."""

from __future__ import annotations

import pytest

from cloudguard.models import Severity
from cloudguard.scanners.iac_scanner import IaCScanner


def scan(source: str) -> list:
    """Analyse a Terraform snippet and return its findings."""
    return IaCScanner().analyse(source, "main.tf")


def rule_ids(source: str) -> set[str]:
    """Rule ids triggered by a Terraform snippet."""
    return {finding.rule_id for finding in scan(source)}


# Every bucket rule fires on a bare bucket; most tests below narrow the
# assertion to the rule under test to stay readable.
BARE_BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'

SECURE_BUCKET = """
resource "aws_s3_bucket" "b" {
  bucket = "x"
}
resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.b.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "b" {
  bucket = aws_s3_bucket.b.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_versioning" "b" {
  bucket = aws_s3_bucket.b.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_logging" "b" {
  bucket        = aws_s3_bucket.b.id
  target_bucket = "logs"
  target_prefix = "b/"
}
"""


class TestS3:
    def test_public_acl_is_critical(self):
        findings = [
            f
            for f in scan(BARE_BUCKET.replace('bucket = "x"', 'acl = "public-read"'))
            if f.rule_id == "CG_IAC_001"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert findings[0].resource == "aws_s3_bucket.b"

    def test_private_acl_is_accepted(self):
        assert "CG_IAC_001" not in rule_ids(
            'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n'
        )

    def test_standalone_acl_resource_is_checked(self):
        assert "CG_IAC_001" in rule_ids(
            """
            resource "aws_s3_bucket_acl" "b" {
              bucket = aws_s3_bucket.b.id
              acl    = "public-read-write"
            }
            """
        )

    def test_bare_bucket_triggers_every_baseline_rule(self):
        assert {"CG_IAC_002", "CG_IAC_003", "CG_IAC_004", "CG_IAC_015"} <= rule_ids(BARE_BUCKET)

    def test_fully_configured_bucket_is_clean(self):
        assert scan(SECURE_BUCKET) == []

    def test_partial_public_access_block_is_reported(self):
        source = SECURE_BUCKET.replace(
            "block_public_policy     = true", "block_public_policy     = false"
        )
        findings = [f for f in scan(source) if f.rule_id == "CG_IAC_002"]
        assert len(findings) == 1
        assert "block_public_policy" in findings[0].message

    def test_companion_resources_may_live_in_another_file(self):
        """The bucket and its guards are frequently split across files."""
        companions = SECURE_BUCKET.replace(
            'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n', ""
        )
        assert 'resource "aws_s3_bucket_public_access_block"' in companions

        scanner = IaCScanner()
        findings = scanner.analyse_files(
            {
                "buckets.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n',
                "security.tf": companions,
            }
        )
        assert [f.rule_id for f in findings] == []

    def test_legacy_inline_configuration_is_understood(self):
        source = """
        resource "aws_s3_bucket" "b" {
          bucket = "x"
          versioning {
            enabled = true
          }
          logging {
            target_bucket = "logs"
          }
          server_side_encryption_configuration {
            rule {
              apply_server_side_encryption_by_default {
                sse_algorithm = "AES256"
              }
            }
          }
        }
        resource "aws_s3_bucket_public_access_block" "b" {
          bucket                  = aws_s3_bucket.b.id
          block_public_acls       = true
          block_public_policy     = true
          ignore_public_acls      = true
          restrict_public_buckets = true
        }
        """
        assert scan(source) == []


class TestSecurityGroups:
    def test_ssh_open_to_the_world_is_critical(self):
        findings = [
            f
            for f in scan(
                """
                resource "aws_security_group" "web" {
                  ingress {
                    from_port   = 22
                    to_port     = 22
                    protocol    = "tcp"
                    cidr_blocks = ["0.0.0.0/0"]
                  }
                }
                """
            )
            if f.rule_id == "CG_IAC_005"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL
        assert "22/SSH" in findings[0].message

    @pytest.mark.parametrize("port", [3389, 3306, 5432, 27017, 6443])
    def test_other_admin_ports_are_critical(self, port: int):
        assert "CG_IAC_005" in rule_ids(
            f"""
            resource "aws_security_group" "web" {{
              ingress {{
                from_port   = {port}
                to_port     = {port}
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }}
            }}
            """
        )

    def test_admin_port_inside_a_range_is_detected(self):
        assert "CG_IAC_005" in rule_ids(
            """
            resource "aws_security_group" "web" {
              ingress {
                from_port   = 20
                to_port     = 30
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """
        )

    def test_non_admin_port_open_to_the_world_is_high(self):
        findings = [
            f
            for f in scan(
                """
                resource "aws_security_group" "web" {
                  ingress {
                    from_port   = 8080
                    to_port     = 8080
                    protocol    = "tcp"
                    cidr_blocks = ["0.0.0.0/0"]
                  }
                }
                """
            )
            if f.rule_id == "CG_IAC_006"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH

    def test_every_protocol_open_to_the_world_is_critical(self):
        findings = [
            f
            for f in scan(
                """
                resource "aws_security_group" "db" {
                  ingress {
                    from_port   = 0
                    to_port     = 0
                    protocol    = "-1"
                    cidr_blocks = ["0.0.0.0/0"]
                  }
                }
                """
            )
            if f.rule_id == "CG_IAC_007"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_ipv6_wildcard_is_detected(self):
        assert "CG_IAC_005" in rule_ids(
            """
            resource "aws_security_group" "web" {
              ingress {
                from_port        = 22
                to_port          = 22
                protocol         = "tcp"
                ipv6_cidr_blocks = ["::/0"]
              }
            }
            """
        )

    def test_restricted_ingress_is_clean(self):
        assert (
            scan(
                """
            resource "aws_security_group" "web" {
              ingress {
                from_port   = 443
                to_port     = 443
                protocol    = "tcp"
                cidr_blocks = ["10.0.0.0/8"]
              }
            }
            """
            )
            == []
        )

    def test_source_security_group_is_clean(self):
        assert (
            scan(
                """
            resource "aws_security_group" "web" {
              ingress {
                from_port       = 22
                to_port         = 22
                protocol        = "tcp"
                security_groups = ["sg-123"]
              }
            }
            """
            )
            == []
        )

    def test_standalone_rule_resource_is_checked(self):
        assert "CG_IAC_005" in rule_ids(
            """
            resource "aws_security_group_rule" "ssh" {
              type              = "ingress"
              from_port         = 22
              to_port           = 22
              protocol          = "tcp"
              cidr_blocks       = ["0.0.0.0/0"]
              security_group_id = "sg-123"
            }
            """
        )

    def test_modern_vpc_rule_resource_is_checked(self):
        assert "CG_IAC_005" in rule_ids(
            """
            resource "aws_vpc_security_group_ingress_rule" "ssh" {
              security_group_id = "sg-123"
              cidr_ipv4         = "0.0.0.0/0"
              from_port         = 22
              to_port           = 22
              ip_protocol       = "tcp"
            }
            """
        )

    def test_open_egress_is_low(self):
        findings = list(
            scan(
                """
                resource "aws_security_group" "web" {
                  egress {
                    from_port   = 0
                    to_port     = 0
                    protocol    = "-1"
                    cidr_blocks = ["0.0.0.0/0"]
                  }
                }
                """
            )
        )
        assert [f.rule_id for f in findings] == ["CG_IAC_017"]
        assert findings[0].severity is Severity.LOW


class TestStorageAndCompute:
    def test_unencrypted_volume(self):
        assert "CG_IAC_008" in rule_ids(
            'resource "aws_ebs_volume" "v" {\n  size = 10\n  encrypted = false\n}\n'
        )

    def test_volume_without_encryption_attribute(self):
        assert "CG_IAC_008" in rule_ids('resource "aws_ebs_volume" "v" {\n  size = 10\n}\n')

    def test_encrypted_volume_is_clean(self):
        assert scan('resource "aws_ebs_volume" "v" {\n  size = 10\n  encrypted = true\n}\n') == []

    def test_instance_without_imdsv2(self):
        assert "CG_IAC_013" in rule_ids('resource "aws_instance" "a" {\n  ami = "ami-1"\n}\n')

    def test_instance_with_optional_tokens(self):
        findings = [
            f
            for f in scan(
                """
                resource "aws_instance" "a" {
                  ami = "ami-1"
                  metadata_options {
                    http_tokens = "optional"
                  }
                }
                """
            )
            if f.rule_id == "CG_IAC_013"
        ]
        assert len(findings) == 1

    def test_instance_with_imdsv2_and_encrypted_root_is_clean(self):
        assert (
            scan(
                """
            resource "aws_instance" "a" {
              ami = "ami-1"
              root_block_device {
                encrypted = true
              }
              metadata_options {
                http_tokens   = "required"
                http_endpoint = "enabled"
              }
            }
            """
            )
            == []
        )


class TestDatabases:
    def test_unencrypted_public_database_without_backups(self):
        ids = rule_ids(
            """
            resource "aws_db_instance" "db" {
              engine                  = "postgres"
              storage_encrypted       = false
              publicly_accessible     = true
              backup_retention_period = 0
            }
            """
        )
        assert {"CG_IAC_009", "CG_IAC_010", "CG_IAC_014"} <= ids

    def test_hardened_database_is_clean(self):
        assert (
            scan(
                """
            resource "aws_db_instance" "db" {
              engine                  = "postgres"
              password                = var.db_password
              storage_encrypted       = true
              publicly_accessible     = false
              backup_retention_period = 14
            }
            """
            )
            == []
        )

    def test_missing_backup_retention_is_reported(self):
        assert "CG_IAC_014" in rule_ids(
            """
            resource "aws_db_instance" "db" {
              engine              = "postgres"
              storage_encrypted   = true
            }
            """
        )


class TestSecrets:
    def test_hardcoded_password(self):
        findings = [
            f
            for f in scan(
                """
                resource "aws_db_instance" "db" {
                  storage_encrypted       = true
                  backup_retention_period = 7
                  password                = "hunter2-production"
                }
                """
            )
            if f.rule_id == "CG_IAC_011"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_variable_reference_is_not_a_secret(self):
        assert "CG_IAC_011" not in rule_ids(
            """
            resource "aws_db_instance" "db" {
              storage_encrypted       = true
              backup_retention_period = 7
              password                = var.db_password
            }
            """
        )

    def test_interpolated_value_is_not_a_secret(self):
        assert "CG_IAC_011" not in rule_ids(
            """
            resource "aws_db_instance" "db" {
              storage_encrypted       = true
              backup_retention_period = 7
              password                = "${data.aws_secretsmanager_secret_version.db.secret_string}"
            }
            """
        )

    def test_aws_access_key_pattern_is_detected(self):
        findings = [
            f
            for f in scan(
                """
                provider "aws" {
                  region     = "eu-west-3"
                  access_key = "AKIAIOSFODNN7EXAMPLE"
                }
                """
            )
            if f.rule_id == "CG_IAC_011"
        ]
        assert len(findings) == 1

    def test_imdsv2_http_tokens_is_not_a_secret(self):
        """`http_tokens = "required"` contains "token" but is not a credential."""
        assert "CG_IAC_011" not in rule_ids(
            """
            resource "aws_instance" "a" {
              ami = "ami-1"
              root_block_device {
                encrypted = true
              }
              metadata_options {
                http_tokens = "required"
              }
            }
            """
        )

    def test_arn_is_not_a_secret(self):
        assert "CG_IAC_011" not in rule_ids(
            """
            resource "aws_kms_alias" "a" {
              secret_arn = "arn:aws:secretsmanager:eu-west-3:123456789012:secret:db"
            }
            """
        )

    def test_sensitive_variable_without_flag(self):
        findings = scan('variable "db_password" {\n  type = string\n}\n')
        assert [f.rule_id for f in findings] == ["CG_IAC_016"]

    def test_sensitive_variable_with_flag_is_clean(self):
        assert scan('variable "db_password" {\n  type = string\n  sensitive = true\n}\n') == []

    def test_variable_default_secret_is_critical(self):
        ids = rule_ids('variable "api_token" {\n  type = string\n  default = "abc123secret"\n}\n')
        assert {"CG_IAC_011", "CG_IAC_016"} == ids


class TestIAM:
    def test_wildcard_policy_via_jsonencode(self):
        findings = [
            f
            for f in scan(
                """
                resource "aws_iam_role_policy" "p" {
                  role   = "r"
                  policy = jsonencode({
                    Version = "2012-10-17"
                    Statement = [
                      { Effect = "Allow", Action = "*", Resource = "*" }
                    ]
                  })
                }
                """
            )
            if f.rule_id == "CG_IAC_012"
        ]
        assert len(findings) == 1
        assert findings[0].severity is Severity.HIGH

    def test_scoped_policy_is_clean(self):
        assert (
            scan(
                """
            resource "aws_iam_role_policy" "p" {
              role   = "r"
              policy = jsonencode({
                Version = "2012-10-17"
                Statement = [
                  {
                    Effect   = "Allow"
                    Action   = ["s3:GetObject"]
                    Resource = ["arn:aws:s3:::bucket/*"]
                  }
                ]
              })
            }
            """
            )
            == []
        )

    def test_wildcard_in_heredoc_json(self):
        assert "CG_IAC_012" in rule_ids(
            """
            resource "aws_iam_policy" "p" {
              policy = <<-EOT
                {
                  "Version": "2012-10-17",
                  "Statement": [
                    {"Effect": "Allow", "Action": "*", "Resource": "*"}
                  ]
                }
              EOT
            }
            """
        )

    def test_wildcard_in_policy_document_data_source(self):
        assert "CG_IAC_012" in rule_ids(
            """
            data "aws_iam_policy_document" "admin" {
              statement {
                effect    = "Allow"
                actions   = ["*"]
                resources = ["*"]
              }
            }
            """
        )

    def test_denied_wildcard_is_not_reported(self):
        assert "CG_IAC_012" not in rule_ids(
            """
            data "aws_iam_policy_document" "deny" {
              statement {
                effect    = "Deny"
                actions   = ["*"]
                resources = ["*"]
              }
            }
            """
        )


class TestScannerBehaviour:
    def test_findings_carry_a_source_snippet_and_remediation(self):
        finding = next(f for f in scan(BARE_BUCKET) if f.rule_id == "CG_IAC_002")
        assert finding.file == "main.tf"
        assert finding.line > 0
        assert finding.remediation
        assert finding.why
        assert finding.category == "terraform"

    def test_broken_file_is_reported_as_an_error_not_a_crash(self):
        scanner = IaCScanner()
        findings = scanner.analyse_files({"broken.tf": 'resource "aws_s3_bucket" "b" {'})
        assert findings == []
        assert scanner.errors and "broken.tf" in scanner.errors[0]

    def test_matches_terraform_files_only(self, tmp_path):
        scanner = IaCScanner()
        assert scanner.matches(tmp_path / "main.tf")
        assert scanner.matches(tmp_path / "prod.tfvars")
        assert not scanner.matches(tmp_path / "main.py")
