###############################################################################
# M6 – Container Image with Secrets
# Mô phỏng: Secret keys embedded trong container images pushed to registry
###############################################################################

# --- 6a. ECR Repository (nơi push image chứa secrets) ---
resource "aws_ecr_repository" "m6_vulnerable_repo" {
  name                 = "${var.project_prefix}-m6-vulnerable-app"
  image_tag_mutability = "MUTABLE" #  Cho phép ghi đè tag → supply chain risk

  #  MISCONFIGURATION: Không bật image scanning
  image_scanning_configuration {
    scan_on_push = false #  Không scan khi push → secrets không bị phát hiện
  }

  #  MISCONFIGURATION: Không mã hóa bằng CMK
  # encryption_configuration không set → dùng AES256 mặc định
  # (nên dùng KMS CMK cho production)

  tags = {
    Name     = "${var.project_prefix}-m6-vulnerable-repo"
    Scenario = "M6-ContainerSecrets"
    Risk     = "CRITICAL"
  }
}

#  ECR Policy cho phép mọi người pull image
resource "aws_ecr_repository_policy" "m6_public_ecr_policy" {
  repository = aws_ecr_repository.m6_vulnerable_repo.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicPull"
        Effect    = "Allow"
        Principal = "*" #  Ai cũng có thể pull image (chứa secrets)
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
        ]
      }
    ]
  })
}

# --- 6b. Dockerfile mẫu chứa secrets (tạo file để demo) ---
resource "local_file" "m6_vulnerable_dockerfile" {
  filename = "${path.module}/docker/Dockerfile.vulnerable"
  content  = <<-DOCKERFILE
#  VULNERABLE DOCKERFILE – Secrets embedded trong image layers
FROM python:3.11-slim

WORKDIR /app

#  MISCONFIGURATION: Hardcode AWS credentials trong Dockerfile
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV AWS_DEFAULT_REGION=ap-southeast-1

#  MISCONFIGURATION: Hardcode database credentials
ENV DB_HOST=prod-database.internal.company.com
ENV DB_USER=admin
ENV DB_PASSWORD=SuperSecret123!
ENV DB_NAME=production

#  MISCONFIGURATION: Hardcode API keys
ENV STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
ENV SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxx

# Copy application code
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

#  MISCONFIGURATION: Copy private key vào image
COPY secrets/private_key.pem /app/secrets/private_key.pem
COPY secrets/ssl_cert.pem /app/secrets/ssl_cert.pem

EXPOSE 8080
CMD ["python", "app.py"]
  DOCKERFILE
}

# --- 6c. Dockerfile an toàn (để so sánh) ---
resource "local_file" "m6_secure_dockerfile" {
  filename = "${path.module}/docker/Dockerfile.secure"
  content  = <<-DOCKERFILE
#  SECURE DOCKERFILE – Không chứa secrets
FROM python:3.11-slim

WORKDIR /app

#  Chạy bằng non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy và install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

#  KHÔNG hardcode credentials – dùng AWS IAM Role / Secrets Manager
# Secrets được inject qua:
# - AWS Secrets Manager
# - ECS Task Role / EKS Service Account
# - Docker secrets / Kubernetes secrets

#  Sử dụng non-root user
USER appuser

EXPOSE 8080
CMD ["python", "app.py"]
  DOCKERFILE
}

# --- 6d. ECS Task Definition tham chiếu image chứa secrets ---
resource "aws_ecs_cluster" "m6_cluster" {
  name = "${var.project_prefix}-m6-cluster"

  tags = {
    Scenario = "M6-ContainerSecrets"
  }
}

resource "aws_iam_role" "m6_ecs_task_role" {
  name = "${var.project_prefix}-m6-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Scenario = "M6-ContainerSecrets"
  }
}

resource "aws_iam_role" "m6_ecs_execution_role" {
  name = "${var.project_prefix}-m6-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Scenario = "M6-ContainerSecrets"
  }
}

resource "aws_iam_role_policy_attachment" "m6_ecs_execution_policy" {
  role       = aws_iam_role.m6_ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

#  ECS Task Definition với secrets hardcode trong environment
resource "aws_ecs_task_definition" "m6_vulnerable_task" {
  family                   = "${var.project_prefix}-m6-vulnerable-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.m6_ecs_execution_role.arn
  task_role_arn            = aws_iam_role.m6_ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "vulnerable-app"
      image = "${aws_ecr_repository.m6_vulnerable_repo.repository_url}:latest"
      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]
      #  MISCONFIGURATION: Secrets trong environment variables (lưu plaintext)
      environment = [
        {
          name  = "DB_HOST"
          value = "prod-database.internal.company.com"
        },
        {
          name  = "DB_PASSWORD"
          value = "SuperSecret123!" #  Password plaintext
        },
        {
          name  = "API_KEY"
          value = "sk_live_EXAMPLE_KEY_12345" #  API key plaintext
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/${var.project_prefix}-m6"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])

  tags = {
    Scenario = "M6-ContainerSecrets"
    Risk     = "CRITICAL"
  }
}
