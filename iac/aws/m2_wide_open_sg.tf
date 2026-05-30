###############################################################################
# M2 – Restricted Network Exposure
# Clean reference: no public ingress, instance in a private subnet.
###############################################################################

resource "aws_vpc" "m2_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name     = "${var.project_prefix}-m2-vpc"
    Scenario = "M2-RestrictedSG"
  }
}

resource "aws_flow_log" "m2_vpc_flow_log" {
  log_destination      = aws_s3_bucket.m1_logs_bucket.arn
  log_destination_type = "s3"
  traffic_type         = "REJECT"
  vpc_id               = aws_vpc.m2_vpc.id
}

resource "aws_subnet" "m2_public_subnet" {
  vpc_id                  = aws_vpc.m2_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name     = "${var.project_prefix}-m2-private-subnet-a"
    Scenario = "M2-RestrictedSG"
  }
}

resource "aws_security_group" "m2_wide_open_sg" {
  name        = "${var.project_prefix}-m2-wide-open-sg"
  description = "SECURE: HTTPS only from internal network"
  vpc_id      = aws_vpc.m2_vpc.id

  ingress {
    description = "HTTPS from internal network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.m2_vpc.cidr_block]
  }

  egress {
    description = "Allow outbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.m2_vpc.cidr_block]
  }

  tags = {
    Name     = "${var.project_prefix}-m2-wide-open-sg"
    Scenario = "M2-RestrictedSG"
    Risk     = "LOW"
  }
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_instance" "m2_exposed_instance" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.m2_public_subnet.id
  vpc_security_group_ids      = [aws_security_group.m2_wide_open_sg.id]
  associate_public_ip_address = false

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  tags = {
    Name     = "${var.project_prefix}-m2-private-instance"
    Scenario = "M2-RestrictedSG"
    Risk     = "LOW"
  }
}
