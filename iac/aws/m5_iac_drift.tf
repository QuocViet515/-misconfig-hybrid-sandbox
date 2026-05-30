###############################################################################
# M5 – IaC Drift
# Safe desired state kept intentionally so you can create post-deployment drift
# later and let runtime scan or drift detection catch it.
###############################################################################

resource "aws_security_group" "m5_intended_sg" {
  name        = "${var.project_prefix}-m5-intended-sg"
  description = "Intended: only HTTPS from the internal network"
  vpc_id      = aws_vpc.m2_vpc.id

  ingress {
    description = "HTTPS only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "HTTPS to internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    Name     = "${var.project_prefix}-m5-intended-sg"
    Scenario = "M5-IaCDrift"
    Risk     = "LOW"
  }
}

resource "local_file" "m5_drift_script" {
  filename = "${path.module}/scripts/m5_simulate_drift.sh"
  content  = <<-BASH
#!/bin/bash
set -euo pipefail

SG_ID="${aws_security_group.m5_intended_sg.id}"

echo "Simulating post-deployment drift on security group $${SG_ID}"
aws ec2 authorize-security-group-ingress \
  --group-id "$${SG_ID}" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0
echo "Drift created. Run terraform plan -refresh-only -detailed-exitcode to detect it."
  BASH
}

resource "local_file" "m5_drift_script_ps" {
  filename = "${path.module}/scripts/m5_simulate_drift.ps1"
  content  = <<-PS1
$SG_ID = "${aws_security_group.m5_intended_sg.id}"

Write-Host "Simulating post-deployment drift on security group $SG_ID"
aws ec2 authorize-security-group-ingress `
  --group-id $SG_ID `
  --protocol tcp `
  --port 22 `
  --cidr 0.0.0.0/0
Write-Host "Drift created. Run terraform plan -refresh-only -detailed-exitcode to detect it."
  PS1
}
