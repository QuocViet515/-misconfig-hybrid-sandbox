# SIEM Quickstart

Repo này hiện hỗ trợ 4 loại document publish vào Elasticsearch:

1. Findings/Triage từ pipeline Python:
   - `scan_results/findings.json`
   - `triage_results/decisions.json`
2. Findings OpenStack custom:
   - `scan_results/openstack_findings.json`
3. Remediation audit events:
   - `artifacts/remediation/runtime_events.json`
   - `artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json`
4. KPI snapshots:
   - `artifacts/remediation/remediation_metrics.json`

## 1) Dựng Elasticsearch + Kibana local

Cách nhanh nhất là dùng stack có sẵn trong repo:

```bash
./scripts/bootstrap_siem.sh
```

Script này sẽ:

- bật `Elasticsearch` và `Kibana`
- import sẵn 3 dashboard capstone
- tạo thêm data view `misconfig-remediation-*` và `misconfig-metrics-*`

Nếu muốn làm thủ công từng bước, dùng compose trực tiếp:

```bash
docker compose -f docker-compose.siem.yml up -d
```

Kiểm tra:

```bash
curl http://localhost:9200
curl http://localhost:5601/api/status
```

Kibana UI:

```text
http://localhost:5601
```

Tắt stack:

```bash
docker compose -f docker-compose.siem.yml down
```

Nếu muốn xóa luôn data:

```bash
docker compose -f docker-compose.siem.yml down -v
```

## 2) Cài dependency Python tối thiểu

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

Để chạy bộ unit test và scanner local:

```bash
./.venv/bin/pip install -r requirements-dev.txt
./.venv/bin/pip install -r requirements-checkov.txt
pytest tests
```

Để chạy full scanner set Terraform local:

```bash
curl -sSfL https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
sudo install -m 0755 ./bin/tfsec /usr/local/bin/tfsec
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
```

Nếu cần ScoutSuite về sau, cài nó trong venv riêng:

```bash
python3 -m venv .scoutsuite-venv
./.scoutsuite-venv/bin/pip install -r requirements-scoutsuite.txt
```

Nếu cần remediation về sau:

```bash
./.venv/bin/pip install -r requirements-remediation.txt
```

## 3) Chạy Checkov + tfsec + Trivy -> Triage

```bash
./.venv/bin/python -m src.scanners.runner \
  --checkov \
  --tfsec \
  --trivy \
  --output-dir ./scan_results \
  --terraform-dir ./iac/terraform \
  --trivy-scan-ref ./iac/terraform

./.venv/bin/python -m src.triage.engine \
  --input ./scan_results/findings.json \
  --output ./triage_results/decisions.json

./.venv/bin/python -m src.triage.notifications \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --output-dir ./artifacts/triage_notifications
```

Nếu muốn dispatch thật tới JIRA / ServiceNow / Slack / Teams thay vì chỉ build artifact:

```bash
./.venv/bin/python -m src.triage.notifications \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --output-dir ./artifacts/triage_notifications \
  --dispatch-live \
  --fail-on-dispatch-error
```

Workflow GitHub `scan_and_remediate` chạy bộ scanner rộng hơn:

- `ScoutSuite`
- `CloudSploit`
- `Checkov`
- `tfsec`
- `Trivy`

## 4) Publish findings và triage vào Elasticsearch

```bash
./.venv/bin/python -m src.siem.publisher \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --pipeline-source local-checkov \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Vì stack local ở trên tắt security, bạn chỉ cần thêm:

```bash
export ELASTICSEARCH_SCHEME=http
export ELASTICSEARCH_HOST=localhost
export ELASTICSEARCH_PORT=9200
```

Biến môi trường hỗ trợ:

- `ELASTICSEARCH_SCHEME`
- `ELASTICSEARCH_HOST`
- `ELASTICSEARCH_PORT`
- `ELASTICSEARCH_USER`
- `ELASTICSEARCH_PASSWORD`
- `ELASTICSEARCH_INDEX_PREFIX`

Nếu chỉ muốn kiểm tra document trước khi gửi:

```bash
./.venv/bin/python -m src.siem.publisher \
  --findings ./scan_results/findings.json \
  --decisions ./triage_results/decisions.json \
  --dry-run \
  --preview-output ./triage_results/es_checkov_preview.json
```

## 5) Kibana data views

Tạo 4 data view:

- `misconfig-findings-*`
- `misconfig-triage-*`
- `misconfig-remediation-*`
- `misconfig-metrics-*`

Time field:

- `@timestamp`

## 6) Dashboard theo wording capstone

Xem:

- [KQL queries](./kibana/kql_queries.md)
- [Dashboard blueprint](./kibana/dashboard_blueprint.md)

## 7) Nối OpenStack findings vào cùng pipeline

Thu thập evidence từ OpenStack lab:

```bash
chmod +x openstack/export_misconfig_openstack.sh
source ~/openrc
PROJECT_PREFIX=threat-demo ./openstack/export_misconfig_openstack.sh
```

Convert evidence thành normalized findings:

```bash
./.venv/bin/python -m src.openstack.findings \
  --container-file reports/raw/openstack/live/container_public.json \
  --sg-rules-file reports/raw/openstack/live/security_group_rules.json \
  --role-assignments-file reports/raw/openstack/live/role_assignments.json \
  --output ./scan_results/openstack_findings.json
```

Publish OpenStack findings vào Elasticsearch:

```bash
./.venv/bin/python -m src.siem.publisher \
  --findings ./scan_results/openstack_findings.json \
  --pipeline-source openstack-lab \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Nếu chưa có Elasticsearch/Kibana local, tạo preview riêng cho đội SIEM:

```bash
./.venv/bin/python -m src.siem.publisher \
  --findings ./scan_results/openstack_findings.json \
  --decisions ./triage_results/openstack_decisions.json \
  --pipeline-source openstack-lab \
  --dry-run \
  --preview-output ./triage_results/es_openstack_preview.json
```

## 8) Publish remediation events và KPI snapshots

Sau khi chạy các flow trong [docs/REMEDIATION.md](./REMEDIATION.md), publish tiếp:

```bash
./.venv/bin/python -m src.siem.publisher \
  --remediation-events ./artifacts/remediation/runtime_events.json \
  --remediation-events ./artifacts/iac_pr/checkov_pr_bundle/iac_pr_events.json \
  --metrics ./artifacts/remediation/remediation_metrics.json \
  --pipeline-source capstone-demo \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

Indices mới:

- `misconfig-remediation-*`
- `misconfig-metrics-*`

Điểm dùng thật trong report/demo:

- `misconfig-remediation-*` cho audit trail remediation runtime và IaC PR-prep
- `misconfig-metrics-*` cho `remediation_rate`, `MTTR`, `open_findings_before/after`, và `iac_pr_prepared_count`
- `artifacts/triage_notifications/` cho owner notification, JIRA payload, ServiceNow payload, và chat alert templates
- `artifacts/drift/m5/` cho M5 drift detection / reconcile / verification evidence
