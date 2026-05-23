###############################################################################
# M3 – IAM Wildcard Policy (Action: "*")
# Mô phỏng: user/role với Action: "*" dẫn tới privilege escalation
###############################################################################

# --- 3a. IAM User với policy Admin full wildcard ---
resource "aws_iam_user" "m3_overprivileged_user" {
  name = "${var.project_prefix}-m3-overprivileged-user"
  path = "/threat-model/"

  tags = {
    Scenario = "M3-IAMWildcard"
    Risk     = "CRITICAL"
  }
}

#  MISCONFIGURATION: Policy cho phép TẤT CẢ action trên TẤT CẢ resource
resource "aws_iam_user_policy" "m3_wildcard_policy" {
  name = "${var.project_prefix}-m3-wildcard-policy"
  user = aws_iam_user.m3_overprivileged_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAdminAccess"
        Effect   = "Allow"
        Action   = "*"           #  WILDCARD – cho phép mọi hành động
        Resource = "*"           #  WILDCARD – trên mọi tài nguyên
      }
    ]
  })
}

# --- 3b. IAM Role với AssumeRole policy lỏng lẻo ---
resource "aws_iam_role" "m3_overprivileged_role" {
  name = "${var.project_prefix}-m3-overprivileged-role"
  path = "/threat-model/"

  #  Cho phép bất kỳ AWS account nào assume role này
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAnyAccountAssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "*"              #  Bất kỳ principal nào trong AWS
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Scenario = "M3-IAMWildcard"
    Risk     = "CRITICAL"
  }
}

resource "aws_iam_role_policy" "m3_role_wildcard_policy" {
  name = "${var.project_prefix}-m3-role-wildcard-policy"
  role = aws_iam_role.m3_overprivileged_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullWildcardAccess"
        Effect   = "Allow"
        Action   = [
          "iam:*",              #  Full IAM access → có thể tạo thêm user/role
          "s3:*",               #  Full S3 access
          "ec2:*",              #  Full EC2 access
          "sts:*",              #  Full STS → có thể assume thêm role khác
        ]
        Resource = "*"
      }
    ]
  })
}

# --- 3c. IAM Group với policy quá rộng ---
resource "aws_iam_group" "m3_admin_group" {
  name = "${var.project_prefix}-m3-admin-group"
  path = "/threat-model/"
}

resource "aws_iam_group_membership" "m3_group_membership" {
  name  = "${var.project_prefix}-m3-group-membership"
  users = [aws_iam_user.m3_overprivileged_user.name]
  group = aws_iam_group.m3_admin_group.name
}

resource "aws_iam_group_policy" "m3_group_policy" {
  name  = "${var.project_prefix}-m3-group-wildcard"
  group = aws_iam_group.m3_admin_group.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassRoleWildcard"
        Effect   = "Allow"
        Action   = [
          "iam:PassRole",         #  Có thể pass bất kỳ role nào
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:AttachUserPolicy",
          "iam:AttachRolePolicy",
        ]
        Resource = "*"            #  Trên mọi resource → privilege escalation
      }
    ]
  })
}

# Access key cho user (để demo, không nên dùng thật)
resource "aws_iam_access_key" "m3_user_key" {
  user = aws_iam_user.m3_overprivileged_user.name
}
