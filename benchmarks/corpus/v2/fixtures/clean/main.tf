# Synthetic AI-built-app fixture — Terraform clean projection.

resource "aws_security_group" "fixture" {
  ingress {
    cidr_blocks = ["10.0.0.0/16"]  # CASE:IAC-08 clean
    from_port   = 443
    to_port     = 443
  }
}

resource "aws_s3_bucket_acl" "fixture" {
  bucket = aws_s3_bucket.fixture.id
  acl    = "private"  # CASE:IAC-09 clean
}

resource "aws_db_instance" "fixture" {
  storage_encrypted = true  # CASE:IAC-10 clean
}

variable "db_password" {
  type      = string
  sensitive = true  # CASE:IAC-11 clean
}
