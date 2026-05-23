# Final Deliverables Checklist

Checklist này gom các artifact đã có trong repo để chốt phần `testing, evaluation & reporting`.

## 1) Dashboard + SIEM

- `artifacts/kibana/misconfig_dashboards.ndjson`
- screenshot của 3 dashboard Kibana
- `docs/SIEM.md`

## 2) Remediation evidence

- `artifacts/remediation/runtime_events.json`
- `artifacts/remediation/remediation_metrics.json`
- `artifacts/iac_pr/checkov_pr_bundle/summary.json`
- `artifacts/iac_pr/checkov_pr_bundle/terraform_fix.patch`
- `artifacts/iac_pr/checkov_pr_bundle/PR_BODY.md`

## 3) Approval / owner review evidence

- `artifacts/triage_notifications/owner_notifications.json`
- `artifacts/triage_notifications/jira_tickets.json`
- `artifacts/triage_notifications/servicenow_incidents.json`
- `artifacts/triage_notifications/chat_notifications.json`
- `artifacts/triage_notifications/dispatch_results.json`
- `artifacts/tickets/iam_wildcard_review/`

## 4) Test evidence

- `docs/TESTING.md`
- kết quả `pytest tests`
- log GitHub Actions của:
  - `scan_and_remediate`
  - `iac_scan`

## 5) Manual deliverables còn phải tự nộp

Phần này repo chỉ chuẩn bị outline và artifact kỹ thuật, bạn vẫn cần tự hoàn tất:

- report cuối
- slide deck
- demo video

## 6) Suggested report structure

1. Problem statement
2. Architecture and pipeline
3. Scanner integration and normalization
4. Triage and approval workflow
5. Automated remediation and IaC PR flow
6. SIEM dashboards and metrics
7. Limitations and future work

## 7) Extra capstone evidence sau phần hardening

- `artifacts/drift/m5/summary.json`
- `artifacts/drift/m5/post_apply_verification.json`
- `artifacts/drift/m5/reconcile_events.json`
