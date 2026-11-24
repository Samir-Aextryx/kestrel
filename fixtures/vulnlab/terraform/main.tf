provider "aws" {
  region = "eu-central-1"
}

resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "vulnlab-assets"
  acl    = "public-read"
  force_destroy = true
}

resource "aws_db_instance" "main" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false
  publicly_accessible = true
  skip_final_snapshot = true
}

resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Resource = "*"
      Effect   = "Allow"
    }]
  })
}
