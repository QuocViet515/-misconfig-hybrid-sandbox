provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  queue_name             = var.queue_name != "" ? var.queue_name : "${var.project_prefix}-postdeploy-events"
  cloudtrail_bucket_name = "${var.project_prefix}-postdeploy-cloudtrail-${data.aws_caller_identity.current.account_id}"

  api_event_pattern = {
    "detail-type" = ["AWS API Call via CloudTrail"]
    "detail" = {
      "eventSource" = [
        "ec2.amazonaws.com",
        "s3.amazonaws.com",
        "iam.amazonaws.com",
      ]
      "eventName" = [
        "AuthorizeSecurityGroupIngress",
        "RevokeSecurityGroupIngress",
        "ModifySecurityGroupRules",
        "CreateSecurityGroup",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock",
        "PutBucketAcl",
        "AttachRolePolicy",
        "AttachUserPolicy",
        "PutRolePolicy",
        "PutUserPolicy",
        "PutGroupPolicy",
      ]
    }
  }

  config_event_pattern = {
    "detail-type" = [
      "Config Configuration Item Change",
      "Config Rules Compliance Change",
    ]
    "source" = ["aws.config"]
  }
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.cloudtrail_bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "postdeploy" {
  name                          = "${var.project_prefix}-postdeploy-events"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${local.queue_name}-dlq"
  message_retention_seconds = 1209600
}

resource "aws_sqs_queue" "events" {
  name                       = local.queue_name
  visibility_timeout_seconds = 120
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgeSendMessage"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.events.arn
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "api_changes" {
  name           = "${var.project_prefix}-postdeploy-api-changes"
  description    = "Forward selected CloudTrail API changes to the post-deploy detection queue."
  event_bus_name = var.event_bus_name
  event_pattern  = jsonencode(local.api_event_pattern)
}

resource "aws_cloudwatch_event_rule" "config_changes" {
  name           = "${var.project_prefix}-postdeploy-config-changes"
  description    = "Forward AWS Config change/compliance events to the post-deploy detection queue."
  event_bus_name = var.event_bus_name
  event_pattern  = jsonencode(local.config_event_pattern)
}

resource "aws_cloudwatch_event_target" "api_queue" {
  rule           = aws_cloudwatch_event_rule.api_changes.name
  event_bus_name = var.event_bus_name
  arn            = aws_sqs_queue.events.arn
}

resource "aws_cloudwatch_event_target" "config_queue" {
  rule           = aws_cloudwatch_event_rule.config_changes.name
  event_bus_name = var.event_bus_name
  arn            = aws_sqs_queue.events.arn
}
