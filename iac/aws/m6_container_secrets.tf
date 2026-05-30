###############################################################################
# M6 – Secure Container Registry Reference
# Clean reference: immutable ECR repo, scan on push, sanitized Dockerfiles.
###############################################################################

resource "aws_kms_key" "m6_ecr_kms_key" {
  description             = "KMS key for ${var.project_prefix} M6 ECR repository"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Scenario = "M6-SecureRegistry"
    Risk     = "LOW"
  }
}

resource "aws_ecr_repository" "m6_vulnerable_repo" {
  name                 = "${var.project_prefix}-m6-secure-app"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.m6_ecr_kms_key.arn
  }

  tags = {
    Name     = "${var.project_prefix}-m6-secure-repo"
    Scenario = "M6-SecureRegistry"
    Risk     = "LOW"
  }
}

resource "local_file" "m6_vulnerable_dockerfile" {
  filename = "${path.module}/docker/Dockerfile.vulnerable"
  content  = <<-DOCKERFILE
FROM python:3.11-slim

WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Reference file kept for compatibility with the demo repo layout.
# No credentials or tokens are embedded in this clean version.

USER appuser

EXPOSE 8080
HEALTHCHECK CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8080), 1)"
CMD ["python", "app.py"]
  DOCKERFILE
}

resource "local_file" "m6_secure_dockerfile" {
  filename = "${path.module}/docker/Dockerfile.secure"
  content  = <<-DOCKERFILE
FROM python:3.11-slim

WORKDIR /app

RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

USER appuser

EXPOSE 8080
HEALTHCHECK CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8080), 1)"
CMD ["python", "app.py"]
  DOCKERFILE
}
