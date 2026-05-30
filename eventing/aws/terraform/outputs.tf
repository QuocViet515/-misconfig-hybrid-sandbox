output "event_queue_url" {
  value       = aws_sqs_queue.events.id
  description = "SQS queue URL consumed by src.events.aws_consumer."
}

output "event_queue_arn" {
  value       = aws_sqs_queue.events.arn
  description = "SQS queue ARN receiving EventBridge messages."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.postdeploy.name
  description = "CloudTrail trail that forwards management events to EventBridge."
}

output "cloudtrail_bucket_name" {
  value       = aws_s3_bucket.cloudtrail.id
  description = "S3 bucket receiving CloudTrail logs for post-deploy detection."
}

output "api_rule_name" {
  value       = aws_cloudwatch_event_rule.api_changes.name
  description = "EventBridge rule forwarding CloudTrail API events."
}

output "config_rule_name" {
  value       = aws_cloudwatch_event_rule.config_changes.name
  description = "EventBridge rule forwarding AWS Config events."
}
