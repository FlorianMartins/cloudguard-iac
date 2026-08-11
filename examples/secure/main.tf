###############################################################################
# ✅ HARDENED REFERENCE — the same infrastructure as ../vulnerable/main.tf,
#    rewritten so that every CloudGuard-IaC rule passes.
#
#    `cloudguard scan-iac examples/secure` exits 0 with zero findings, and the
#    CI pipeline asserts it on every commit.
###############################################################################

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# No credentials in code: the provider reads them from the environment, an SSO
# profile or the CI OIDC role.
provider "aws" {
  region = "eu-west-3"
}

# ---------------------------------------------------------------------------
# Variables — secrets are declared, never valued
# ---------------------------------------------------------------------------

variable "db_password" {
  description = "Database password, injected from the secret store at plan time"
  type        = string
  sensitive   = true
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "corporate_cidrs" {
  description = "CIDR ranges allowed to reach the public entry point"
  type        = list(string)
  default     = ["203.0.113.0/24", "198.51.100.0/24"]
}

# ---------------------------------------------------------------------------
# Encryption key
# ---------------------------------------------------------------------------

resource "aws_kms_key" "data" {
  description             = "CMK for customer data at rest"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# ---------------------------------------------------------------------------
# Storage — private, encrypted, versioned, logged
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-exports-${var.environment}"

  tags = {
    Name        = "customer-exports"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_public_access_block" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "customer_exports" {
  bucket = aws_s3_bucket.customer_exports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "customer_exports" {
  bucket        = aws_s3_bucket.customer_exports.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3/customer-exports/"
}

# The log bucket itself follows the same baseline. Access logging is
# deliberately not enabled on it — a bucket logging into itself creates an
# infinite object loop — so the rule is suppressed with an explicit reason.
# cloudguard:ignore CG_IAC_015 log destination bucket, self-logging would loop
resource "aws_s3_bucket" "access_logs" {
  bucket = "acme-access-logs-${var.environment}"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# ---------------------------------------------------------------------------
# Network — least privilege in, controlled egress out
# ---------------------------------------------------------------------------

resource "aws_security_group" "bastion" {
  name        = "bastion-sg"
  description = "Session Manager endpoint, no inbound rule"
  vpc_id      = "vpc-0123456789abcdef0"
}

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web tier security group"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "HTTPS from corporate ranges only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.corporate_cidrs
  }

  ingress {
    description     = "Administrative access through the bastion only"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description = "Outbound HTTPS to the VPC endpoints and the patch mirror"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "database" {
  name        = "database-sg"
  description = "Database tier, reachable from the web tier only"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description     = "PostgreSQL from the web tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }
}

# ---------------------------------------------------------------------------
# Compute — encrypted volumes, IMDSv2 enforced
# ---------------------------------------------------------------------------

resource "aws_ebs_volume" "app_data" {
  availability_zone = "eu-west-3a"
  size              = 100
  encrypted         = true
  kms_key_id        = aws_kms_key.data.arn

  tags = {
    Name = "app-data"
  }
}

resource "aws_instance" "app" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.medium"
  vpc_security_group_ids = [aws_security_group.web.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  root_block_device {
    volume_size = 50
    encrypted   = true
    kms_key_id  = aws_kms_key.data.arn
  }

  # IMDSv2 only: an SSRF can no longer read the instance role credentials.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = {
    Name = "app-server"
  }
}

# ---------------------------------------------------------------------------
# Database — encrypted, private, backed up, secret from the vault
# ---------------------------------------------------------------------------

resource "aws_db_instance" "main" {
  identifier              = "acme-production-db"
  engine                  = "postgres"
  engine_version          = "15.5"
  instance_class          = "db.t3.medium"
  allocated_storage       = 100
  username                = "app_admin"
  password                = var.db_password
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.data.arn
  publicly_accessible     = false
  backup_retention_period = 14
  deletion_protection     = true
  skip_final_snapshot     = false
  final_snapshot_identifier = "acme-production-db-final"
  vpc_security_group_ids  = [aws_security_group.database.id]
}

# ---------------------------------------------------------------------------
# IAM — least privilege, scoped to the resources actually used
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "app-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_instance_profile" "app" {
  name = "app-instance-profile"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy" "app" {
  name = "app-policy"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadWriteOwnExports"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = ["${aws_s3_bucket.customer_exports.arn}/*"]
      },
      {
        Sid      = "DecryptWithDataKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.data.arn]
      },
    ]
  })
}
