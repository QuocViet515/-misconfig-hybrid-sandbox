variable "aws_region" {
  type        = string
  default     = "ap-southeast-1"
  description = "AWS region where EventBridge and SQS should run."
}

variable "project_prefix" {
  type        = string
  default     = "threat-demo"
  description = "Common prefix for event-driven resources."
}

variable "event_bus_name" {
  type        = string
  default     = "default"
  description = "EventBridge bus name."
}

variable "queue_name" {
  type        = string
  default     = ""
  description = "Override the SQS queue name. Leave empty to derive from project_prefix."
}

