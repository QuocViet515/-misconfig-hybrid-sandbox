###############################################################################
# M4 – Encrypted Storage
# Clean reference: encrypted EBS, S3, and RDS.
###############################################################################

resource "aws_kms_key" "m4_storage_kms_key" {
  description             = "KMS key for secure M4 storage resources"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Scenario = "M4-EncryptedStorage"
    Risk     = "LOW"
  }
}

resource "aws_ebs_volume" "m4_unencrypted_volume" {
  availability_zone = "${var.aws_region}a"
  size              = 10
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.m4_storage_kms_key.arn

  tags = {
    Name     = "${var.project_prefix}-m4-encrypted-ebs"
    Scenario = "M4-EncryptedStorage"
    Risk     = "LOW"
  }
}

resource "aws_ebs_snapshot" "m4_unencrypted_snapshot" {
  volume_id = aws_ebs_volume.m4_unencrypted_volume.id

  tags = {
    Name     = "${var.project_prefix}-m4-encrypted-snapshot"
    Scenario = "M4-EncryptedStorage"
    Risk     = "LOW"
  }
}

resource "aws_s3_bucket" "m4_unencrypted_bucket" {
  bucket        = "${var.project_prefix}-m4-encrypted-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name     = "${var.project_prefix}-m4-encrypted-bucket"
    Scenario = "M4-EncryptedStorage"
    Risk     = "LOW"
  }
}

resource "aws_s3_bucket_ownership_controls" "m4_bucket_ownership" {
  bucket = aws_s3_bucket.m4_unencrypted_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "m4_bucket_public_access" {
  bucket = aws_s3_bucket.m4_unencrypted_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "m4_bucket_versioning" {
  bucket = aws_s3_bucket.m4_unencrypted_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "m4_bucket_encryption" {
  bucket = aws_s3_bucket.m4_unencrypted_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.m4_storage_kms_key.arn
    }
  }
}

resource "aws_s3_bucket_logging" "m4_bucket_logging" {
  bucket        = aws_s3_bucket.m4_unencrypted_bucket.id
  target_bucket = aws_s3_bucket.m1_logs_bucket.id
  target_prefix = "m4-encrypted-bucket/"
}

resource "aws_s3_bucket_policy" "m4_bucket_ssl_only" {
  bucket = aws_s3_bucket.m4_unencrypted_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.m4_unencrypted_bucket.arn,
          "${aws_s3_bucket.m4_unencrypted_bucket.arn}/*",
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

resource "aws_s3_object" "m4_unencrypted_object" {
  bucket                 = aws_s3_bucket.m4_unencrypted_bucket.id
  key                    = "reference/configuration/app_config.json"
  server_side_encryption = "AES256"
  content = jsonencode({
    host        = "app-db.internal.example.com"
    port        = 5432
    username    = "service-account"
    environment = "production"
  })

  tags = {
    Classification = "INTERNAL"
  }
}

resource "aws_subnet" "m4_private_subnet" {
  vpc_id                  = aws_vpc.m2_vpc.id
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "${var.aws_region}b"

  tags = {
    Name     = "${var.project_prefix}-m4-private-subnet"
    Scenario = "M4-EncryptedStorage"
  }
}

resource "aws_db_subnet_group" "m4_db_subnet" {
  name       = "${var.project_prefix}-m4-db-subnet"
  subnet_ids = [aws_subnet.m2_public_subnet.id, aws_subnet.m4_private_subnet.id]

  tags = {
    Scenario = "M4-EncryptedStorage"
  }
}

resource "aws_db_instance" "m4_unencrypted_rds" {
  identifier                          = "${var.project_prefix}-m4-encrypted-rds"
  engine                              = "mysql"
  engine_version                      = "8.0"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  storage_type                        = "gp3"
  storage_encrypted                   = true
  db_name                             = "appdb"
  username                            = "dbadmin"
  manage_master_user_password         = true
  db_subnet_group_name                = aws_db_subnet_group.m4_db_subnet.name
  vpc_security_group_ids              = [aws_security_group.m2_wide_open_sg.id]
  skip_final_snapshot                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  enabled_cloudwatch_logs_exports     = ["audit", "error", "general", "slowquery"]

  tags = {
    Name     = "${var.project_prefix}-m4-encrypted-rds"
    Scenario = "M4-EncryptedStorage"
    Risk     = "LOW"
  }
}
