# Misconfig Hybrid Sandbox

Repo này là bản sandbox để test trước workflow `hybrid cloud` mà chưa đụng vào branch chính `feat/normalize`.

Mục tiêu của sandbox:

- test `self-hosted runner` cho OpenStack
- test workflow `.github/workflows/hybrid_runtime_scan.yml`
- test secrets / runner labels / OpenStack auth / AWS auth
- test publish findings vào SIEM

## 1) Cần có gì trên runner

Máy chạy `self-hosted runner` nên có:

- `python3`
- `git`
- `curl`
- `openstack` CLI
- `aws` CLI
- access tới OpenStack API
- access tới AWS API

Xem chi tiết:

- [docs/SELF_HOSTED_RUNNER.md](./docs/SELF_HOSTED_RUNNER.md)

## 2) Workflow cần test

Workflow chính của sandbox:

- [.github/workflows/hybrid_runtime_scan.yml](./.github/workflows/hybrid_runtime_scan.yml)

Workflow này sẽ:

1. quét `AWS runtime + IaC`
2. export `OpenStack evidence`
3. normalize thành `hybrid_findings.json`
4. triage + notification artifacts
5. optional publish vào Elasticsearch
6. optional remediation / `M5 drift` / IaC PR bundle

## 3) Cách test nhanh

### A. Register self-hosted runner

Tạo runner cho repo này với labels:

- `self-hosted`
- `linux`
- `openstack`

### B. Chuẩn bị auth

Trên runner host:

```bash
source ~/openrc
openstack token issue
aws sts get-caller-identity
```

### C. Nếu muốn xem dashboard local

```bash
./scripts/bootstrap_siem.sh
```

### D. Chạy workflow

Vào GitHub:

1. `Actions`
2. `Hybrid runtime scan (self-hosted)`
3. `Run workflow`

Input khuyến nghị:

- `include_aws_scan = true`
- `include_openstack_scan = true`
- `publish_to_siem = true`
- `dispatch_live_integrations = false`
- `enable_runtime_remediation = false`
- `reconcile_m5_drift = false`
- `generate_iac_pr = true`
- `openrc_path = ~/openrc`
- `project_prefix = threat-demo`

## 4) File nên mở sau khi chạy

- `scan_results/hybrid_findings.json`
- `triage_results/hybrid_decisions.json`
- `artifacts/triage_notifications/`
- `artifacts/iac_pr/`
- `artifacts/drift/`

## 5) Nếu sandbox ổn

Khi mọi thứ chạy ổn trên sandbox:

1. copy/push workflow + docs về repo chính
2. merge vào `feat/normalize`
3. dùng repo chính cho demo/report cuối
