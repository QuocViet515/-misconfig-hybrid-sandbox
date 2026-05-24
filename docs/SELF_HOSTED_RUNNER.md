# Self-Hosted Runner For OpenStack

Tài liệu này giải thích cách biến phần `OpenStack` của đồ án thành một workflow tự động đúng tinh thần MD:

- GitHub Actions vẫn là trigger/orchestration layer
- nhưng job chạy trên `self-hosted runner` nằm trong lab/private network
- runner này mới có thể nhìn thấy `OpenStack API`, `openrc`, và các tài nguyên hybrid thật

## 1) Vì sao cần self-hosted runner

`GitHub-hosted runner` quét tốt:

- code trong repo
- IaC
- AWS runtime qua public APIs + credentials

Nhưng nó **không tự nhìn thấy OpenStack lab** nếu lab chỉ reachable trong:

- LAN
- VPN
- private subnet
- all-in-one control plane nội bộ

Vì vậy phần `hybrid cloud` đúng chuẩn MD nên chạy qua một workflow duy nhất:

- `hybrid_runtime_scan.yml`: `AWS + OpenStack + IaC` trên runner nội bộ

## 2) Workflow đã thêm trong repo

Workflow chính:

- [.github/workflows/hybrid_runtime_scan.yml](/home/deployer/Desktop/Misconfig_AutoRemediate_Project/.github/workflows/hybrid_runtime_scan.yml)

Workflow này chạy trên labels:

- `self-hosted`
- `linux`
- `openstack`

Nó hỗ trợ:

- AWS runtime scan (`ScoutSuite`, `CloudSploit`)
- IaC scan (`Checkov`, `tfsec`, `Trivy`)
- OpenStack evidence export + normalize
- merge findings thành `hybrid_findings.json`
- triage + notification artifacts / live dispatch
- publish findings + decisions vào Elasticsearch
- optional runtime remediation
- optional `M5` drift reconcile
- optional IaC PR bundle generation

## 3) Máy runner nên đặt ở đâu

Nên đặt runner trên:

- chính `OpenStack control plane`
- hoặc một `Ubuntu VM` trong cùng network với OpenStack API
- hoặc một `jump host` có:
  - `openstack` CLI hoạt động
  - access tới AWS APIs
  - access tới Elasticsearch/Kibana nếu muốn publish local

## 4) Prerequisites trên runner host

Runner host cần có sẵn ít nhất:

- `git`
- `bash`
- `curl`
- `python3`
- `pip`
- `openstack` CLI
- `aws` CLI
- network tới GitHub
- network tới OpenStack API

Khuyến nghị thêm:

- `docker` nếu muốn chạy `bootstrap_siem.sh` local
- `terraform` nếu muốn chạy `M5 drift` trên host ngoài workflow

Lưu ý:
- workflow tự cài `Checkov`, `ScoutSuite`, `tfsec`, `Trivy`, `OPA`
- workflow **không tự cài** `openstack` CLI hay `aws` CLI

## 5) Cấu hình GitHub self-hosted runner

Tại repo GitHub:

1. `Settings`
2. `Actions`
3. `Runners`
4. `New self-hosted runner`
5. chọn `Linux`
6. làm theo lệnh GitHub cung cấp

Khuyến nghị gán labels:

- `openstack`
- `hybrid-lab`

Ví dụ, sau khi config runner:

```bash
./config.sh \
  --url https://github.com/<owner>/<repo> \
  --token <runner-registration-token> \
  --labels openstack,hybrid-lab
```

Sau đó cài runner như service:

```bash
sudo ./svc.sh install
sudo ./svc.sh start
```

## 6) Chuẩn bị OpenStack auth trên runner

Runner host cần có file `openrc`, ví dụ:

```bash
~/openrc
```

Kiểm tra:

```bash
source ~/openrc
openstack token issue
```

Workflow mặc định sẽ dùng:

- `~/openrc`

nhưng có thể đổi qua input:

- `openrc_path`

## 7) Chuẩn bị AWS auth trên runner

Có 2 cách:

1. cấu hình trực tiếp trên runner host:

```bash
aws configure
aws sts get-caller-identity
```

2. hoặc dùng credentials/role mà runner host đã có sẵn trong environment

Workflow hiện verify bằng:

```bash
aws sts get-caller-identity
```

## 8) Nếu muốn publish vào SIEM local

Trên runner host, bật Elasticsearch + Kibana:

```bash
cd /home/deployer/Desktop/Misconfig_AutoRemediate_Project
./scripts/bootstrap_siem.sh
```

Nếu Elasticsearch không ở `localhost:9200`, set repository secrets:

- `ELASTICSEARCH_HOST`
- `ELASTICSEARCH_PORT`
- `ELASTICSEARCH_SCHEME`

## 9) Cách chạy workflow hybrid

Vào:

1. `Actions`
2. `Hybrid runtime scan (self-hosted)`
3. `Run workflow`

Input khuyến nghị để demo:

- `include_aws_scan = true`
- `include_openstack_scan = true`
- `publish_to_siem = true`
- `dispatch_live_integrations = false`
- `enable_runtime_remediation = false`
- `reconcile_m5_drift = false`
- `generate_iac_pr = true`
- `project_prefix = threat-demo`
- `aws_region = ap-southeast-1`
- `openrc_path = ~/openrc`
- `pipeline_source = github-self-hosted-hybrid`

## 10) Cách chạy workflow hybrid có remediation

Cho demo remediation mạnh hơn:

- `enable_runtime_remediation = true`
- `reconcile_m5_drift = true`
- `simulate_m5_drift = true`

Nếu bạn muốn thử full cutover cho `M4 RDS`:

- `force_rds_cutover = true`
- `delete_archived_rds = true`

Chỉ bật hai cờ này trong lab riêng, không bật trên môi trường đang dùng thật.

## 11) Artifact và output chính

Workflow sẽ upload artifact:

- `hybrid-runtime-artifacts`

Bên trong có:

- `scan_results/`
- `triage_results/`
- `artifacts/triage_notifications/`
- `artifacts/remediation/`
- `artifacts/iac_pr/`
- `artifacts/drift/`

File quan trọng nhất:

- `scan_results/hybrid_findings.json`
- `triage_results/hybrid_decisions.json`
- `artifacts/remediation/hybrid_metrics.json`

## 12) Cách giải thích khi bảo vệ

Bạn có thể nói ngắn như sau:

1. `GitHub-hosted runner` được dùng cho `IaC/AWS public workflows`
2. `self-hosted runner` được dùng cho `OpenStack/private runtime workflows`
3. cả hai đều đổ vào cùng một:
   - normalizer
   - triage engine
   - SIEM
   - remediation/audit path

Đó là cách hệ thống đạt đúng tinh thần `hybrid cloud automation` trong MD.
