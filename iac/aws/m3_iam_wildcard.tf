###############################################################################
# M3 – Least-Privilege IAM
# Clean reference: scoped permissions and no access keys.
###############################################################################

resource "aws_iam_user" "m3_overprivileged_user" {
  name = "${var.project_prefix}-m3-app-user"
  path = "/application/"

  tags = {
    Scenario = "M3-LeastPrivilegeIAM"
    Risk     = "LOW"
  }
}

resource "aws_iam_role" "m3_overprivileged_role" {
  name = "${var.project_prefix}-m3-app-role"
  path = "/application/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEc2AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Scenario = "M3-LeastPrivilegeIAM"
    Risk     = "LOW"
  }
}

resource "aws_iam_role_policy" "m3_role_wildcard_policy" {
  name = "${var.project_prefix}-m3-role-readonly-policy"
  role = aws_iam_role.m3_overprivileged_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadReferenceBucket"
        Effect = "Allow"
        Action = ["s3:ListBucket"]
        Resource = [
          aws_s3_bucket.m1_policy_public_bucket.arn,
        ]
      },
      {
        Sid    = "ReadReferenceObjects"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = [
          "${aws_s3_bucket.m1_policy_public_bucket.arn}/*",
        ]
      }
    ]
  })
}
