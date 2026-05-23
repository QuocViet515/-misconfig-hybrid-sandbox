# Remediation Flows

Tài liệu này chốt 4 phần còn lại của capstone sau khi scan, triage, và 3 dashboard Kibana đã hoàn thành:

1. export dashboard artifacts
2. runtime remediation flow
3. IaC fix / PR-prep flow
4. remediation metrics + audit publish vào Elasticsearch

## 1) Export dashboard artifacts

```bash
cd /home/deployer/Desktop/Misconfig_AutoRemediate_Project
./.venv/bin/python scripts/export_kibana_dashboards.py
```

Artifacts:

- `artifacts/kibana/misconfig_dashboards.ndjson`
- `artifacts/kibana/dashboard_manifest.json`

## 2) Runtime remediation flow

Executor:

```bash
./.venv/bin/python -m src.remediation.runtime_executor \
  --findings ./scan_results/openstack_findings.json \
  --decisions ./triage_results/openstack_decisions.json \
  --approve-all-manual \
  --simulate-success \
  --pipeline-source openstack-runtime-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Artifacts:

- `artifacts/remediation/runtime_events.json`
- `artifacts/remediation/findings_after_runtime.json`

Ghi chú:

- `--simulate-success` dùng cho demo/audit trail mà không thay đổi cloud thật.
- Để chạy thật trên OpenStack lab, bỏ `--simulate-success` và thêm `--execute`.
- Flow hiện hỗ trợ:
  - `OPENSTACK_SWIFT_PUBLIC_READ`
  - `OPENSTACK_SG_WIDE_OPEN`
  - `OPENSTACK_PROJECT_ADMIN_ASSIGNMENT`

### AWS runtime remediation

Executor:

```bash
./.venv/bin/python -m src.remediation.aws_runtime_executor \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --region ap-southeast-1 \
  --project-prefix threat-demo \
  --approve-all-manual \
  --simulate-success \
  --pipeline-source aws-runtime-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Flow này triển khai 3 nhánh:

- `M1 Public S3` qua Cloud Custodian policy runtime
- `M2 Wide-open SG` qua Ansible playbook `ansible/remediate_open_sg.yml`
- `M4 Unencrypted storage` qua AWS API orchestration trong `src/remediation/aws_runtime_executor.py`

Artifacts:

- `artifacts/remediation/aws_runtime_events.json`
- `artifacts/remediation/aws_findings_after_runtime.json`
- `artifacts/remediation/custodian/`
- `artifacts/remediation/ansible/`

#### M4 RDS cutover modes

Mặc định, `M4` sẽ tạo encrypted replacement cho RDS và dừng ở trạng thái `pending-cutover` để tránh tự động đập dịch vụ đang chạy. Nếu bạn chấp nhận cutover thật, bật thêm:

```bash
./.venv/bin/python -m src.remediation.aws_runtime_executor \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --region ap-southeast-1 \
  --project-prefix threat-demo \
  --approve-all-manual \
  --execute \
  --force-rds-cutover \
  --delete-archived-rds
```

Khi đó flow sẽ:

1. snapshot DB gốc
2. copy snapshot sang encrypted snapshot
3. rename DB gốc sang archived identifier
4. restore DB encrypted mới về lại identifier ban đầu
5. tùy chọn xóa archived DB nếu có `--delete-archived-rds`

### IAM wildcard manual review ticket

```bash
./.venv/bin/python -m src.remediation.opa_ticket \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --output-dir ./artifacts/tickets/iam_wildcard_review \
  --pipeline-source opa-iam-review \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Artifacts:

- `artifacts/tickets/iam_wildcard_review/input.json`
- `artifacts/tickets/iam_wildcard_review/opa_result.json`
- `artifacts/tickets/iam_wildcard_review/SECURITY_REVIEW_TICKET.md`
- `artifacts/tickets/iam_wildcard_review/review_events.json`

### Generic owner / ticket notification artifacts

```bash
./.venv/bin/python -m src.triage.notifications \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --output-dir ./artifacts/triage_notifications
```

Để dispatch thật tới JIRA / ServiceNow / Slack / Teams:

```bash
export JIRA_URL="https://your-domain.atlassian.net"
export JIRA_EMAIL="security-bot@example.com"
export JIRA_API_TOKEN="..."
export SERVICENOW_URL="https://instance.service-now.com"
export SERVICENOW_USER="security_bot"
export SERVICENOW_PASSWORD="..."
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export TEAMS_WEBHOOK_URL="https://..."

./.venv/bin/python -m src.triage.notifications \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --output-dir ./artifacts/triage_notifications \
  --dispatch-live \
  --fail-on-dispatch-error
```

Artifacts:

- `artifacts/triage_notifications/owner_notifications.json`
- `artifacts/triage_notifications/jira_tickets.json`
- `artifacts/triage_notifications/servicenow_incidents.json`
- `artifacts/triage_notifications/chat_notifications.json`
- `artifacts/triage_notifications/dispatch_results.json`

### M5 drift reconcile end-to-end

Flow này làm rõ kịch bản `runtime drift -> detect -> reconcile -> verify` cho `M5`:

```bash
./.venv/bin/python -m src.remediation.drift_reconcile \
  --terraform-dir ./iac/terraform \
  --region ap-southeast-1 \
  --project-prefix threat-demo \
  --simulate-drift \
  --execute \
  --pipeline-source local-m5-drift \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)" \
  --output-dir ./artifacts/drift/m5
```

Artifacts:

- `artifacts/drift/m5/simulate_drift.json`
- `artifacts/drift/m5/plan.json`
- `artifacts/drift/m5/summary.json`
- `artifacts/drift/m5/post_apply_verification.json`
- `artifacts/drift/m5/reconcile_events.json`

## 3) IaC fix / PR-prep flow

Generator:

```bash
./.venv/bin/python -m src.remediation.iac_pr_prepare \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --terraform-dir ./iac/terraform \
  --output-dir ./artifacts/iac_pr \
  --run-label checkov_pr_bundle \
  --pipeline-source iac-pr-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Artifacts:

- `artifacts/iac_pr/checkov_pr_bundle/terraform_fix.patch`
- `artifacts/iac_pr/checkov_pr_bundle/PR_BODY.md`
- `artifacts/iac_pr/checkov_pr_bundle/summary.json`
- `artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json`
- `artifacts/iac_pr/checkov_pr_bundle/fixed_tree/`

Flow này hiện auto-generate patch cho:

- `m1_public_s3.tf`
- `m2_wide_open_sg.tf`
- `m4_unencrypted_storage.tf`

Unsupported findings vẫn được liệt kê ở:

- `artifacts/iac_pr/checkov_pr_bundle/unsupported_findings.json`

Để mở PR thật từ bundle:

```bash
./.venv/bin/python -m src.remediation.open_fix_pr \
  --bundle-dir ./artifacts/iac_pr/checkov_pr_bundle \
  --repo-root . \
  --repo "${GITHUB_REPOSITORY}" \
  --token "${GITHUB_TOKEN}" \
  --base-branch main
```

## 4) Metrics và audit publish vào Elasticsearch

Gộp snapshot hybrid:

```bash
./.venv/bin/python scripts/merge_json_collections.py \
  --inputs ./scan_results/findings.json ./scan_results/openstack_findings.json \
  --output ./artifacts/remediation/findings_hybrid.json

./.venv/bin/python scripts/merge_json_collections.py \
  --inputs ./triage_results/decisions.json ./triage_results/openstack_decisions.json \
  --collection-key decisions \
  --output ./artifacts/remediation/decisions_hybrid.json
```

Build KPI snapshot:

```bash
./.venv/bin/python -m src.remediation.metrics \
  --findings ./artifacts/remediation/findings_hybrid.json \
  --decisions ./artifacts/remediation/decisions_hybrid.json \
  --remediation-events ./artifacts/remediation/runtime_events.json \
  --remediation-events ./artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json \
  --pipeline-source capstone-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)" \
  --output ./artifacts/remediation/remediation_metrics.json
```

Publish remediation events và metrics:

```bash
./.venv/bin/python -m src.siem.publisher \
  --remediation-events ./artifacts/remediation/runtime_events.json \
  --remediation-events ./artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json \
  --remediation-events ./artifacts/drift/m5/reconcile_events.json \
  --metrics ./artifacts/remediation/remediation_metrics.json \
  --pipeline-source capstone-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Indices:

- `misconfig-remediation-*`
- `misconfig-metrics-*`

## Expected deliverables

Khi nộp bài, phần remediation/reporting giờ có thể lấy trực tiếp từ các thư mục sau:

- `artifacts/kibana/`
- `artifacts/remediation/`
- `artifacts/iac_pr/`

## Honest limitations

- `MTTR` hiện phản ánh timestamp demo giữa `detected_at` và thời điểm chạy remediation, chưa phải production MTTR.
- `Compliance score` hiện là proxy qua `cis_findings_before/after`, chưa phải benchmark score đầy đủ.
- `M4` RDS mặc định vẫn chạy ở safe mode `pending-cutover`; full cutover chỉ xảy ra khi bật `--force-rds-cutover`.
- Live integrations yêu cầu bạn tự cấp secret hợp lệ cho JIRA / ServiceNow / Slack / Teams.
