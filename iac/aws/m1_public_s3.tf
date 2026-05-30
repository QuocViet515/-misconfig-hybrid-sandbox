###############################################################################
# M1 – Secure S3 Buckets
# Clean reference: private buckets, public access blocked, encryption enabled.
###############################################################################

resource "aws_s3_bucket" "m1_logs_bucket" {
  bucket        = "${var.project_prefix}-m1-logs-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Scenario = "M1-SecureS3Logs"
    Risk     = "LOW"
  }
}

resource "aws_kms_key" "m1_s3_kms_key" {
  description             = "KMS key for secure M1 S3 buckets"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Scenario = "M1-SecureS3"
    Risk     = "LOW"
  }
}

resource "aws_s3_bucket_ownership_controls" "m1_logs_ownership" {
  bucket = aws_s3_bucket.m1_logs_bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_public_access_block" "m1_logs_public_access" {
  bucket = aws_s3_bucket.m1_logs_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "m1_logs_acl" {
  depends_on = [
    aws_s3_bucket_ownership_controls.m1_logs_ownership,
    aws_s3_bucket_public_access_block.m1_logs_public_access,
  ]

  bucket = aws_s3_bucket.m1_logs_bucket.id
  acl    = "log-delivery-write"
}

resource "aws_s3_bucket_versioning" "m1_logs_versioning" {
  bucket = aws_s3_bucket.m1_logs_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "m1_logs_encryption" {
  bucket = aws_s3_bucket.m1_logs_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "m1_logs_ssl_only" {
  bucket = aws_s3_bucket.m1_logs_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.m1_logs_bucket.arn,
          "${aws_s3_bucket.m1_logs_bucket.arn}/*",
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

resource "aws_s3_bucket" "m1_public_bucket" {
  bucket        = "${var.project_prefix}-m1-private-bucket-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Scenario = "M1-SecureS3"
    Risk     = "LOW"
  }
}

resource "aws_s3_bucket_ownership_controls" "m1_ownership" {
  bucket = aws_s3_bucket.m1_public_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "m1_public_access" {
  bucket = aws_s3_bucket.m1_public_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "m1_public_bucket_versioning" {
  bucket = aws_s3_bucket.m1_public_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "m1_public_bucket_encryption" {
  bucket = aws_s3_bucket.m1_public_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.m1_s3_kms_key.arn
    }
  }
}

resource "aws_s3_bucket_logging" "m1_public_bucket_logging" {
  bucket        = aws_s3_bucket.m1_public_bucket.id
  target_bucket = aws_s3_bucket.m1_logs_bucket.id
  target_prefix = "m1-public-bucket/"
}

resource "aws_s3_bucket_policy" "m1_public_bucket_ssl_only" {
  bucket = aws_s3_bucket.m1_public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.m1_public_bucket.arn,
          "${aws_s3_bucket.m1_public_bucket.arn}/*",
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

resource "aws_s3_bucket" "m1_policy_public_bucket" {
  bucket        = "${var.project_prefix}-m1-policy-private-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Scenario = "M1-SecureS3Policy"
    Risk     = "LOW"
  }
}

resource "aws_s3_bucket_ownership_controls" "m1_policy_ownership" {
  bucket = aws_s3_bucket.m1_policy_public_bucket.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "m1_policy_public_access" {
  bucket = aws_s3_bucket.m1_policy_public_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "m1_policy_bucket_versioning" {
  bucket = aws_s3_bucket.m1_policy_public_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "m1_policy_bucket_encryption" {
  bucket = aws_s3_bucket.m1_policy_public_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.m1_s3_kms_key.arn
    }
  }
}

resource "aws_s3_bucket_logging" "m1_policy_bucket_logging" {
  bucket        = aws_s3_bucket.m1_policy_public_bucket.id
  target_bucket = aws_s3_bucket.m1_logs_bucket.id
  target_prefix = "m1-policy-bucket/"
}

resource "aws_s3_bucket_policy" "m1_public_policy" {
  bucket = aws_s3_bucket.m1_policy_public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.m1_policy_public_bucket.arn,
          "${aws_s3_bucket.m1_policy_public_bucket.arn}/*",
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

resource "aws_s3_object" "m1_sensitive_file" {
  bucket                 = aws_s3_bucket.m1_public_bucket.id
  key                    = "reference-data/customer_records.csv"
  server_side_encryption = "AES256"
  content                = <<-EOF
    customer_id,name,email
    1,Nguyen Van A,nva@example.com
    2,Tran Thi B,ttb@example.com
  EOF

  tags = {
    Classification = "INTERNAL"
  }
}
