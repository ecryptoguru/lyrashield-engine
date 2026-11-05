# Synthetic AI-built-app fixture — Terraform cases.

resource "aws_security_group" "fixture" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]  # CASE:IAC-08
    from_port   = 22
    to_port     = 22
  }
}

resource "aws_s3_bucket_acl" "fixture" {
  bucket = aws_s3_bucket.fixture.id
  acl    = "public-read"  # CASE:IAC-09
}

resource "aws_db_instance" "fixture" {
  encrypted = false  # CASE:IAC-10
}

variable "db_password" {
  default = "fixture-secret-placeholder-tf01"  # CASE:IAC-11
}
