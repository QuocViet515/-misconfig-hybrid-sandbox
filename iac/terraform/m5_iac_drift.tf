###############################################################################
# M5 – IaC Drift
# Mô phỏng: Môi trường runtime bị chỉnh sửa thủ công khác với IaC → misconfig
#
# Cách demo:
# 1. Triển khai Terraform → tạo SG chỉ cho phép port 443
# 2. Chỉnh sửa thủ công trên Console: thêm rule mở port 22 cho 0.0.0.0/0
# 3. Chạy "terraform plan" → phát hiện drift
#
# File này tạo trạng thái ban đầu "an toàn" – drift sẽ xảy ra khi ai đó
# sửa thủ công qua AWS Console/CLI mà không cập nhật code Terraform.
###############################################################################

# Security Group "an toàn" ban đầu (chỉ HTTPS)
resource "aws_security_group" "m5_intended_sg" {
  name        = "${var.project_prefix}-m5-intended-sg"
  description = "Intended: Only HTTPS allowed. Drift = manual changes outside IaC"
  vpc_id      = aws_vpc.m2_vpc.id

  # Rule hợp lệ: chỉ cho phép HTTPS
  ingress {
    description = "HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # Chỉ nội bộ
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name     = "${var.project_prefix}-m5-intended-sg"
    Scenario = "M5-IaCDrift"
    Risk     = "MEDIUM"
    Note     = "Run 'terraform plan' after manual changes to detect drift"
  }

  # ignore_changes có thể được dùng để MÔ PHỎNG drift:
  # Nếu bật lifecycle ignore, Terraform sẽ không phát hiện thay đổi thủ công.
  # Ở đây ta KHÔNG ignore để Terraform có thể phát hiện drift.
}

# Script giả lập drift bằng AWS CLI
# Sau khi terraform apply, chạy script này để tạo drift:
resource "local_file" "m5_drift_script" {
  filename = "${path.module}/scripts/m5_simulate_drift.sh"
  content  = <<-BASH
#!/bin/bash
###############################################################################
# Script mô phỏng IaC Drift – chỉnh sửa SG thủ công bằng AWS CLI
# Chạy sau khi "terraform apply" để tạo drift
###############################################################################

SG_ID="${aws_security_group.m5_intended_sg.id}"
echo "=== Simulating IaC Drift ==="
echo "Security Group: $SG_ID"

# Thêm rule SSH mở toàn bộ (drift so với Terraform state)
echo "[DRIFT] Adding SSH rule (port 22) open to 0.0.0.0/0..."
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# Thêm rule MySQL mở toàn bộ
echo "[DRIFT] Adding MySQL rule (port 3306) open to 0.0.0.0/0..."
aws ec2 authorize-security-group-ingress \
  --group-id "$SG_ID" \
  --protocol tcp \
  --port 3306 \
  --cidr 0.0.0.0/0

echo ""
echo "=== Drift created! Now run 'terraform plan' to detect changes ==="
echo "Expected: Terraform will show the manually added rules as drift"
  BASH
}

# PowerShell version cho Windows
resource "local_file" "m5_drift_script_ps" {
  filename = "${path.module}/scripts/m5_simulate_drift.ps1"
  content  = <<-PS1
###############################################################################
# Script mô phỏng IaC Drift – chỉnh sửa SG thủ công bằng AWS CLI
# Chạy sau khi "terraform apply" để tạo drift
###############################################################################

$SG_ID = "${aws_security_group.m5_intended_sg.id}"
Write-Host "=== Simulating IaC Drift ==="
Write-Host "Security Group: $SG_ID"

# Thêm rule SSH mở toàn bộ (drift so với Terraform state)
Write-Host "[DRIFT] Adding SSH rule (port 22) open to 0.0.0.0/0..."
aws ec2 authorize-security-group-ingress `
  --group-id $SG_ID `
  --protocol tcp `
  --port 22 `
  --cidr 0.0.0.0/0

# Thêm rule MySQL mở toàn bộ
Write-Host "[DRIFT] Adding MySQL rule (port 3306) open to 0.0.0.0/0..."
aws ec2 authorize-security-group-ingress `
  --group-id $SG_ID `
  --protocol tcp `
  --port 3306 `
  --cidr 0.0.0.0/0

Write-Host ""
Write-Host "=== Drift created! Now run 'terraform plan' to detect changes ==="
Write-Host "Expected: Terraform will show the manually added rules as drift"
  PS1
}
