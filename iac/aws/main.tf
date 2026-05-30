terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Dùng data source để lấy account ID hiện tại
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
