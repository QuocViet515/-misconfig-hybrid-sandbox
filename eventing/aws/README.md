# AWS Event-Driven Post-Deploy Detection

Mục tiêu: khi ai đó sửa S3 / security group / IAM trên AWS bằng console, CLI hoặc SDK, EventBridge sẽ đẩy event vào SQS; `src.events.aws_consumer` đọc queue, enrich trạng thái runtime hiện tại, rồi sinh findings, triage, publish lên Elasticsearch, và tùy chọn gọi remediation hiện có.

## 1. Provision EventBridge + SQS

```bash
cd eventing/aws/terraform
terraform init
terraform apply -var="aws_region=ap-southeast-1" -var="project_prefix=threat-demo"
```

Sau khi apply, lấy `event_queue_url` từ output.

## 2. Bật nguồn event ở AWS

- `CloudTrail` phải ghi `Management events`.
- `AWS Config` nên bật recorder cho:
  - `AWS::EC2::SecurityGroup`
  - `AWS::S3::Bucket`
  - `AWS::IAM::Role`
  - `AWS::IAM::User`
  - `AWS::IAM::Policy`

Stack Terraform này chỉ tạo rule + queue; nó không tự bật CloudTrail/AWS Config nếu account của bạn chưa có.

## 3. Replay nhanh bằng payload mẫu

Trước khi nối queue thật, bạn có thể replay payload mẫu:

```bash
cd /home/deployer/Desktop/-misconfig-hybrid-sandbox
python -m src.events.aws_consumer \
  --event-file eventing/aws/samples/open_sg_event.json \
  --region ap-southeast-1
```

Sửa `sg-REPLACE_ME` trong sample trước khi chạy.

## 4. Chạy consumer trên control node

```bash
cd /home/deployer/Desktop/-misconfig-hybrid-sandbox
python -m src.events.aws_consumer \
  --sqs-queue-url "<EVENT_QUEUE_URL>" \
  --region ap-southeast-1 \
  --project-prefix threat-demo \
  --publish-to-siem \
  --execute-remediation \
  --build-metrics \
  --delete-consumed
```

Kết quả:

- findings: `artifacts/events/aws/findings.json`
- decisions: `artifacts/events/aws/decisions.json`
- remediation events: `artifacts/events/aws/remediation/aws_runtime_events.json`
- metrics: `artifacts/events/aws/remediation_metrics.json`

## 5. Supported AWS detections

- Security group mở `0.0.0.0/0` hoặc `::/0` cho `22`, `3389`, hoặc `all traffic`
- Bucket S3 lộ public qua:
  - public access block bị tắt
  - policy status public
  - ACL public
- IAM principal gắn policy wildcard `Action="*"` + `Resource="*"`

## 6. Remediation behavior

- S3 public: route sang nhánh runtime remediation `public_s3`
- Security group wide-open: route sang `open_security_group`
- IAM wildcard: chỉ detect + manual review, không auto-remediate
