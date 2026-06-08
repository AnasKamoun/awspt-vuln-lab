terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

# Untrusted input flows in via variables (CLI -var / TF_VAR_* env / tfvars).
variable "region" {
  type    = string
  default = "us-east-1"
}

# CWE-798: Hardcoded AWS access key id used as a provider/variable default.
variable "aws_access_key" {
  type    = string
  default = "AKIAIOSFODNN7EXAMPLE"
}

# CWE-798: Hardcoded AWS secret access key (fake).
variable "aws_secret_key" {
  type    = string
  default = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# CWE-798: Hardcoded DB master password supplied as a default.
variable "db_password" {
  type    = string
  default = "Sup3rS3cr3tP@ssw0rd!"
}

variable "ingress_cidr" {
  type    = string
  default = "0.0.0.0/0"
}

variable "bucket_name" {
  type    = string
  default = "my-public-lab-bucket-2026"
}

# CWE-798 / CWE-321: Static long-lived credentials baked into the provider.
provider "aws" {
  region     = var.region
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

# CWE-284: Security group exposing SSH and RDP to the entire internet.
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "intentionally insecure"

  # CWE-732 / CWE-284: SSH open to 0.0.0.0/0.
  ingress {
    description = "ssh from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ingress_cidr]
  }

  # CWE-284: RDP open to 0.0.0.0/0.
  ingress {
    description = "rdp from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # CWE-1327: Unrestricted egress to anywhere.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# CWE-200: World-readable S3 bucket (public-read ACL).
resource "aws_s3_bucket" "public_data" {
  bucket = var.bucket_name
}

# CWE-732: ACL grants public-read to everyone.
resource "aws_s3_bucket_acl" "public_data_acl" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"
}

# Note: NO aws_s3_bucket_public_access_block resource defined (CWE-732).
# Note: NO aws_s3_bucket_server_side_encryption_configuration (CWE-311).

# CWE-311 / CWE-200: RDS instance unencrypted, public, hardcoded password.
resource "aws_db_instance" "lab_db" {
  identifier          = "lab-db"
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = var.db_password # CWE-798: hardcoded secret flows here
  storage_encrypted   = false           # CWE-311: encryption disabled
  publicly_accessible = true            # CWE-284: reachable from internet
  skip_final_snapshot = true
}

# CWE-269: IAM policy granting full admin (Action="*", Resource="*").
resource "aws_iam_policy" "god_mode" {
  name = "god-mode-policy"

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

# CWE-532: Hardcoded credential echoed into a publicly resolvable output.
output "leaked_secret_key" {
  value = var.aws_secret_key
}

# CWE-778: VPC declared but NO aws_flow_log resource attached (no flow logs).
resource "aws_vpc" "lab" {
  cidr_block = "10.0.0.0/16"
}
