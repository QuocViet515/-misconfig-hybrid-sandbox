###############################################################################
# Outputs – Hiển thị thông tin sau khi apply
###############################################################################

# ── M1: Public S3 ──
output "m1_public_bucket_name" {
  description = "M1: S3 bucket with public ACL"
  value       = aws_s3_bucket.m1_public_bucket.id
}

output "m1_public_bucket_url" {
  description = "M1: URL truy cập public bucket"
  value       = "https://${aws_s3_bucket.m1_public_bucket.bucket_regional_domain_name}"
}

output "m1_policy_public_bucket" {
  description = "M1: S3 bucket with overly permissive bucket policy"
  value       = aws_s3_bucket.m1_policy_public_bucket.id
}

# ── M2: Wide-open Security Group ──
output "m2_wide_open_sg_id" {
  description = "M2: Security Group ID mở SSH/RDP cho 0.0.0.0/0"
  value       = aws_security_group.m2_wide_open_sg.id
}

output "m2_exposed_instance_id" {
  description = "M2: EC2 Instance ID với SG wide-open"
  value       = aws_instance.m2_exposed_instance.id
}

# ── M3: IAM Wildcard ──
output "m3_overprivileged_user" {
  description = "M3: IAM user với wildcard policy"
  value       = aws_iam_user.m3_overprivileged_user.name
}

output "m3_overprivileged_role_arn" {
  description = "M3: IAM role ARN với Action: '*'"
  value       = aws_iam_role.m3_overprivileged_role.arn
}

output "m3_access_key_id" {
  description = "M3: Access Key ID (demo only)"
  value       = aws_iam_access_key.m3_user_key.id
  sensitive   = true
}

# ── M4: Unencrypted Storage ──
output "m4_unencrypted_ebs_id" {
  description = "M4: Unencrypted EBS Volume ID"
  value       = aws_ebs_volume.m4_unencrypted_volume.id
}

output "m4_unencrypted_bucket" {
  description = "M4: S3 bucket không có server-side encryption"
  value       = aws_s3_bucket.m4_unencrypted_bucket.id
}

output "m4_unencrypted_rds_endpoint" {
  description = "M4: RDS endpoint không mã hóa"
  value       = aws_db_instance.m4_unencrypted_rds.endpoint
}

# ── M5: IaC Drift ──
output "m5_intended_sg_id" {
  description = "M5: SG ID – chạy script drift rồi 'terraform plan' để phát hiện"
  value       = aws_security_group.m5_intended_sg.id
}

output "m5_drift_script_path" {
  description = "M5: Path tới script mô phỏng drift"
  value       = local_file.m5_drift_script.filename
}

# ── M6: Container Secrets ──
output "m6_ecr_repository_url" {
  description = "M6: ECR repository URL (chứa image có secrets)"
  value       = aws_ecr_repository.m6_vulnerable_repo.repository_url
}

output "m6_vulnerable_dockerfile_path" {
  description = "M6: Path tới Dockerfile chứa secrets"
  value       = local_file.m6_vulnerable_dockerfile.filename
}

output "m6_secure_dockerfile_path" {
  description = "M6: Path tới Dockerfile an toàn (so sánh)"
  value       = local_file.m6_secure_dockerfile.filename
}

# ── Summary ──
output "summary" {
  description = "Tóm tắt các kịch bản"
  value = <<-EOT

  ╔══════════════════════════════════════════════════════════════╗
  ║          THREAT MODEL – ATTACK SCENARIOS DEPLOYED           ║
  ╠══════════════════════════════════════════════════════════════╣
  ║ M1 – Public S3 Bucket          → ACL + Bucket Policy lỗi  ║
  ║ M2 – Wide-open Security Group  → SSH/RDP exposed 0.0.0.0/0║
  ║ M3 – IAM Wildcard Policy       → Action: "*" trên mọi res ║
  ║ M4 – Unencrypted Storage       → EBS/S3/RDS plaintext     ║
  ║ M5 – IaC Drift                 → Chạy script rồi tf plan  ║
  ║ M6 – Container Image Secrets   → Creds trong Dockerfile   ║
  ╠══════════════════════════════════════════════════════════════╣
  ║   CHỈ DÙNG CHO MỤC ĐÍCH HỌC TẬP – KHÔNG DEPLOY PROD    ║
  ║ 🧹 Chạy "terraform destroy" sau khi demo xong!             ║
  ╚══════════════════════════════════════════════════════════════╝
  EOT
}
