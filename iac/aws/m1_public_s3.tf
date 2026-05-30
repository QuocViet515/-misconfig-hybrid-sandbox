###############################################################################
# M1 – Public S3 Bucket
# Mô phỏng: Dữ liệu nhạy cảm bị public do ACL lỗi hoặc bucket policy
###############################################################################

# --- 1a. S3 Bucket với ACL public-read (sai cấu hình ACL) ---
resource "aws_s3_bucket" "m1_public_bucket" {
  bucket        = "${var.project_prefix}-m1-public-bucket-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Scenario = "M1-PublicS3"
    Risk     = "HIGH"
  }
}


resource "aws_s3_bucket_ownership_controls" "m1_ownership" {
  bucket = aws_s3_bucket.m1_public_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

#  MISCONFIGURATION: Public ACL
resource "aws_s3_bucket_public_access_block" "m1_public_access" {
  bucket = aws_s3_bucket.m1_public_bucket.id

  block_public_acls       = false #  Không chặn public ACL
  block_public_policy     = false #  Không chặn public policy
  ignore_public_acls      = false #  Không bỏ qua public ACL
  restrict_public_buckets = false #  Không giới hạn public bucket
}

resource "aws_s3_bucket_acl" "m1_public_acl" {
  depends_on = [
    aws_s3_bucket_ownership_controls.m1_ownership,
    aws_s3_bucket_public_access_block.m1_public_access,
  ]

  bucket = aws_s3_bucket.m1_public_bucket.id
  acl    = "public-read" #  Ai cũng có thể đọc
}

# --- 1b. S3 Bucket với Bucket Policy cho phép truy cập ẩn danh ---
resource "aws_s3_bucket" "m1_policy_public_bucket" {
  bucket        = "${var.project_prefix}-m1-policy-public-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Scenario = "M1-PublicS3Policy"
    Risk     = "HIGH"
  }
}

resource "aws_s3_bucket_public_access_block" "m1_policy_public_access" {
  bucket = aws_s3_bucket.m1_policy_public_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

#  MISCONFIGURATION: Bucket policy cho phép Principal = "*"
resource "aws_s3_bucket_policy" "m1_public_policy" {
  depends_on = [aws_s3_bucket_public_access_block.m1_policy_public_access]
  bucket     = aws_s3_bucket.m1_policy_public_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*" #  Bất kỳ ai
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.m1_policy_public_bucket.arn}/*"
      }
    ]
  })
}

# Upload file mẫu chứa "dữ liệu nhạy cảm"
resource "aws_s3_object" "m1_sensitive_file" {
  bucket  = aws_s3_bucket.m1_public_bucket.id
  key     = "sensitive-data/customer_records.csv"
  content = <<-EOF
    customer_id,name,email,ssn
    1,Nguyen Van A,nva@example.com,123-45-6789
    2,Tran Thi B,ttb@example.com,987-65-4321
  EOF

  tags = {
    Classification = "CONFIDENTIAL"
  }
}
