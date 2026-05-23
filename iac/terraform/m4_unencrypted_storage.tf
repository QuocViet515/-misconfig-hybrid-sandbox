###############################################################################
# M4 – Unencrypted Storage
# Mô phỏng: snapshot/volume/object không có encryption-at-rest
###############################################################################

# --- 4a. EBS Volume KHÔNG mã hóa ---
resource "aws_ebs_volume" "m4_unencrypted_volume" {
  availability_zone = "${var.aws_region}a"
  size              = 10
  encrypted         = false #  MISCONFIGURATION: Không mã hóa

  tags = {
    Name     = "${var.project_prefix}-m4-unencrypted-ebs"
    Scenario = "M4-UnencryptedStorage"
    Risk     = "HIGH"
  }
}

# --- 4b. EBS Snapshot từ volume không mã hóa ---
resource "aws_ebs_snapshot" "m4_unencrypted_snapshot" {
  volume_id = aws_ebs_volume.m4_unencrypted_volume.id

  tags = {
    Name     = "${var.project_prefix}-m4-unencrypted-snapshot"
    Scenario = "M4-UnencryptedStorage"
    Risk     = "HIGH"
  }
}

# --- 4c. S3 Bucket KHÔNG có server-side encryption ---
resource "aws_s3_bucket" "m4_unencrypted_bucket" {
  bucket        = "${var.project_prefix}-m4-unencrypted-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name     = "${var.project_prefix}-m4-unencrypted-bucket"
    Scenario = "M4-UnencryptedStorage"
    Risk     = "HIGH"
  }
}

# Không cấu hình server_side_encryption_configuration → dữ liệu lưu plaintext
# (Trong thực tế AWS có default encryption, nhưng đây là demo misconfiguration)

# Upload file nhạy cảm mà không chỉ định encryption
resource "aws_s3_object" "m4_unencrypted_object" {
  bucket  = aws_s3_bucket.m4_unencrypted_bucket.id
  key     = "secrets/database_credentials.json"
  content = jsonencode({
    host     = "prod-db.internal.example.com"
    port     = 5432
    username = "admin"
    password = "SuperSecretP@ss123!" #  Password hardcoded
    database = "production"
  })
  #  Không có server_side_encryption → lưu plaintext

  tags = {
    Classification = "CONFIDENTIAL"
  }
}

# --- 4d. RDS Instance KHÔNG mã hóa ---
resource "aws_db_subnet_group" "m4_db_subnet" {
  name       = "${var.project_prefix}-m4-db-subnet"
  subnet_ids = [aws_subnet.m2_public_subnet.id, aws_subnet.m4_private_subnet.id]

  tags = {
    Scenario = "M4-UnencryptedStorage"
  }
}

resource "aws_subnet" "m4_private_subnet" {
  vpc_id            = aws_vpc.m2_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}b"

  tags = {
    Name     = "${var.project_prefix}-m4-private-subnet"
    Scenario = "M4-UnencryptedStorage"
  }
}

resource "aws_db_instance" "m4_unencrypted_rds" {
  identifier     = "${var.project_prefix}-m4-unencrypted-rds"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"

  allocated_storage = 20
  storage_encrypted = false #  MISCONFIGURATION: RDS không mã hóa

  db_name  = "mydb"
  username = "admin"
  password = "insecure-password-123" #  Password hardcoded trong code

  db_subnet_group_name   = aws_db_subnet_group.m4_db_subnet.name
  vpc_security_group_ids = [aws_security_group.m2_wide_open_sg.id]
  skip_final_snapshot    = true
  publicly_accessible    = false

  tags = {
    Name     = "${var.project_prefix}-m4-unencrypted-rds"
    Scenario = "M4-UnencryptedStorage"
    Risk     = "HIGH"
  }
}
