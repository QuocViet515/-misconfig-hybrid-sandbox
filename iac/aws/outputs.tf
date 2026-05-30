###############################################################################
# Outputs – Clean reference values
###############################################################################

output "m1_public_bucket_name" {
  description = "M1 clean reference bucket name"
  value       = aws_s3_bucket.m1_public_bucket.id
}

output "m1_public_bucket_url" {
  description = "M1 clean reference bucket URL"
  value       = "https://${aws_s3_bucket.m1_public_bucket.bucket_regional_domain_name}"
}

output "m1_policy_public_bucket" {
  description = "M1 clean reference policy-controlled bucket"
  value       = aws_s3_bucket.m1_policy_public_bucket.id
}

output "m2_wide_open_sg_id" {
  description = "M2 clean reference security group ID"
  value       = aws_security_group.m2_wide_open_sg.id
}

output "m2_exposed_instance_id" {
  description = "M2 clean reference instance ID"
  value       = aws_instance.m2_exposed_instance.id
}

output "m3_overprivileged_user" {
  description = "M3 clean reference IAM user"
  value       = aws_iam_user.m3_overprivileged_user.name
}

output "m3_overprivileged_role_arn" {
  description = "M3 clean reference IAM role ARN"
  value       = aws_iam_role.m3_overprivileged_role.arn
}

output "m3_access_key_id" {
  description = "No access key is generated in the clean reference"
  value       = null
  sensitive   = true
}

output "m4_unencrypted_ebs_id" {
  description = "M4 clean reference encrypted EBS volume ID"
  value       = aws_ebs_volume.m4_unencrypted_volume.id
}

output "m4_unencrypted_bucket" {
  description = "M4 clean reference encrypted S3 bucket"
  value       = aws_s3_bucket.m4_unencrypted_bucket.id
}

output "m4_unencrypted_rds_endpoint" {
  description = "M4 clean reference encrypted RDS endpoint"
  value       = aws_db_instance.m4_unencrypted_rds.endpoint
}

output "m5_intended_sg_id" {
  description = "M5 drift baseline security group"
  value       = aws_security_group.m5_intended_sg.id
}

output "m5_drift_script_path" {
  description = "Path to the drift simulation script"
  value       = local_file.m5_drift_script.filename
}

output "m6_ecr_repository_url" {
  description = "M6 clean reference ECR repository URL"
  value       = aws_ecr_repository.m6_vulnerable_repo.repository_url
}

output "m6_vulnerable_dockerfile_path" {
  description = "Compatibility path for the sanitized reference Dockerfile"
  value       = local_file.m6_vulnerable_dockerfile.filename
}

output "m6_secure_dockerfile_path" {
  description = "Path to the secure reference Dockerfile"
  value       = local_file.m6_secure_dockerfile.filename
}

output "summary" {
  description = "Summary of the clean reference baseline"
  value       = <<-EOT

  Clean hybrid Terraform reference deployed.
  - M1: private and encrypted S3 buckets with access logging
  - M2: restricted security group and private EC2 instance
  - M3: least-privilege IAM user, group, and role
  - M4: encrypted EBS, S3, and RDS resources
  - M5: safe drift baseline to modify manually after deployment
  - M6: secure ECR repository and sanitized Dockerfile references
  EOT
}

