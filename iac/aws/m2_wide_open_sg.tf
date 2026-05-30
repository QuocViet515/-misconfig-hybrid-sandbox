###############################################################################
# M2 – Security Group Wide Open (0.0.0.0/0)
# Mô phỏng: SSH/RDP exposed ra toàn bộ internet
###############################################################################

# VPC cho demo
resource "aws_vpc" "m2_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name     = "${var.project_prefix}-m2-vpc"
    Scenario = "M2-WideOpenSG"
  }
}

resource "aws_subnet" "m2_public_subnet" {
  vpc_id                  = aws_vpc.m2_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = {
    Name     = "${var.project_prefix}-m2-public-subnet"
    Scenario = "M2-WideOpenSG"
  }
}

#  MISCONFIGURATION: Security Group mở toàn bộ SSH & RDP cho 0.0.0.0/0
resource "aws_security_group" "m2_wide_open_sg" {
  name        = "${var.project_prefix}-m2-wide-open-sg"
  description = "INSECURE: SSH and RDP open to the world"
  vpc_id      = aws_vpc.m2_vpc.id

  #  SSH mở cho toàn bộ internet
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #  Toàn bộ IPv4
  }

  #  RDP mở cho toàn bộ internet
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] #  Toàn bộ IPv4
  }

  #  Mở ALL traffic inbound
  ingress {
    description = "All traffic from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] #  Tất cả port, tất cả protocol
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name     = "${var.project_prefix}-m2-wide-open-sg"
    Scenario = "M2-WideOpenSG"
    Risk     = "CRITICAL"
  }
}

# EC2 instance gắn SG wide-open (dùng Amazon Linux 2 AMI)
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
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.m2_public_subnet.id
  vpc_security_group_ids = [aws_security_group.m2_wide_open_sg.id]

  tags = {
    Name     = "${var.project_prefix}-m2-exposed-instance"
    Scenario = "M2-WideOpenSG"
    Risk     = "CRITICAL"
  }
}
