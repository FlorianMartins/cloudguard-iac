###############################################################################
# ⚠️  VULNERABLE BY DESIGN — DO NOT DEPLOY  ⚠️
#
# This file exists so CloudGuard-IaC has something to find, and so the CI
# pipeline can prove it blocks a build. Every block below is a real-world
# misconfiguration seen in production Terraform.
#
# The secured counterpart lives in ../secure/main.tf.
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

provider "aws" {
  region = "eu-west-3"

  # CG_IAC_011 — long-lived credentials committed to the repository.
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

# CG_IAC_016 + CG_IAC_011 — a secret variable, unprotected, with a default value.
variable "db_password" {
  description = "Password of the application database"
  type        = string
  default     = "SuperSecret123!"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

# ---------------------------------------------------------------------------
# Storage — a bucket wide open to the Internet
# ---------------------------------------------------------------------------

# CG_IAC_001 — public ACL.
# CG_IAC_002 — no public access block.
# CG_IAC_003 — no server-side encryption.
# CG_IAC_004 — no versioning.
# CG_IAC_015 — no access logging.
resource "aws_s3_bucket" "customer_exports" {
  bucket = "acme-customer-exports-${var.environment}"
  acl    = "public-read"

  tags = {
    Name        = "customer-exports"
    Environment = var.environment
  }
}

# ---------------------------------------------------------------------------
# Network — a security group that is not a security control
# ---------------------------------------------------------------------------

resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web tier security group"
  vpc_id      = "vpc-0123456789abcdef0"

  # CG_IAC_005 — SSH open to the entire Internet.
  ingress {
    description = "SSH from anywhere, for convenience"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CG_IAC_006 — application port open to the entire Internet.
  ingress {
    description = "Admin console"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CG_IAC_017 — unrestricted egress.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# CG_IAC_007 — every port, every protocol, from everywhere.
resource "aws_security_group" "database" {
  name        = "database-sg"
  description = "Database tier"
  vpc_id      = "vpc-0123456789abcdef0"

  ingress {
    description = "Allow everything from everywhere"
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------------
# Compute — unencrypted disks and IMDSv1
# ---------------------------------------------------------------------------

# CG_IAC_008 — unencrypted volume.
resource "aws_ebs_volume" "app_data" {
  availability_zone = "eu-west-3a"
  size              = 100
  encrypted         = false

  tags = {
    Name = "app-data"
  }
}

# CG_IAC_008 — unencrypted root device.
# CG_IAC_013 — no metadata_options, so IMDSv1 (SSRF → credentials) stays open.
resource "aws_instance" "app" {
  ami                    = "ami-0123456789abcdef0"
  instance_type          = "t3.medium"
  vpc_security_group_ids = [aws_security_group.web.id]

  root_block_device {
    volume_size = 50
    encrypted   = false
  }

  user_data = <<-EOT
    #!/bin/bash
    echo "DB_PASSWORD=${var.db_password}" >> /etc/app/.env
    curl -fsSL https://get.example.com/agent.sh | bash
  EOT

  tags = {
    Name = "app-server"
  }
}

# ---------------------------------------------------------------------------
# Database — unencrypted, public, no backups, plaintext password
# ---------------------------------------------------------------------------

# CG_IAC_009 — storage not encrypted.
# CG_IAC_010 — publicly accessible.
# CG_IAC_014 — automated backups disabled.
# CG_IAC_011 — password written in clear.
resource "aws_db_instance" "main" {
  identifier              = "acme-production-db"
  engine                  = "postgres"
  engine_version          = "15.5"
  instance_class          = "db.t3.medium"
  allocated_storage       = 100
  username                = "app_admin"
  password                = "P@ssw0rd-production-2024"
  storage_encrypted       = false
  publicly_accessible     = true
  backup_retention_period = 0
  skip_final_snapshot     = true
  vpc_security_group_ids  = [aws_security_group.database.id]
}

# ---------------------------------------------------------------------------
# IAM — an administrator disguised as an application role
# ---------------------------------------------------------------------------

resource "aws_iam_role" "app" {
  name = "app-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

# CG_IAC_012 — full administrative access.
resource "aws_iam_role_policy" "app" {
  name = "app-policy"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
