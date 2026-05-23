# Hybrid Cloud Lab Quickstart

Mục tiêu hiện tại: triển khai Cloud B (OpenStack) với 3 misconfiguration tối thiểu để chạy chung pipeline với AWS.

## 1) Prerequisites

- Ubuntu control plane đã cài `python-openstackclient`.
- Có file `openrc` từ OpenStack all-in-one.
- Đã đăng nhập OpenStack API thành công.
- Nếu muốn GitHub tự scan OpenStack/private lab, xem thêm [docs/SELF_HOSTED_RUNNER.md](./SELF_HOSTED_RUNNER.md).

```bash
source ~/openrc
openstack token issue
```

## 2) Deploy 3 Misconfigurations on OpenStack (Cloud B)

Từ root repo:

```bash
chmod +x openstack/deploy_misconfig_openstack.sh
source ~/openrc
PROJECT_PREFIX=threat-demo DEMO_PASSWORD='ChangeMe123!' ./openstack/deploy_misconfig_openstack.sh
```

Script sẽ tạo:

- M1: Swift container public read (`.r:*,.rlistings`)
- M2: Security group mở `22/tcp`, `3389/tcp`, `all` từ `0.0.0.0/0`
- M3: User được gán role `admin` trên project demo

## 3) Verify

```bash
openstack container show threat-demo-m1-public-container -f yaml
openstack security group rule list threat-demo-m2-wide-open-sg
openstack role assignment list --project threat-demo-m3-overpriv-project --user threat-demo-m3-overpriv-user --names
```

## 4) Cleanup

```bash
chmod +x openstack/cleanup_misconfig_openstack.sh
source ~/openrc
PROJECT_PREFIX=threat-demo ./openstack/cleanup_misconfig_openstack.sh
```

## 5) Export Raw Evidence For Pipeline

```bash
chmod +x openstack/export_misconfig_openstack.sh
source ~/openrc
PROJECT_PREFIX=threat-demo ./openstack/export_misconfig_openstack.sh
```

Convert raw evidence thành normalized findings:

```bash
./.venv/bin/python -m src.openstack.findings \
  --container-file reports/raw/openstack/live/container_public.json \
  --sg-rules-file reports/raw/openstack/live/security_group_rules.json \
  --role-assignments-file reports/raw/openstack/live/role_assignments.json \
  --output ./scan_results/openstack_findings.json
```

Publish findings lên Elasticsearch:

```bash
./.venv/bin/python -m src.siem.publisher \
  --findings ./scan_results/openstack_findings.json \
  --pipeline-source openstack-lab \
  --branch feat/normalize \
  --commit-sha "$(git rev-parse --short HEAD)"
```

## 6) Notes

- Chỉ chạy trong lab, không chạy trên môi trường production.
- Nếu bạn đổi tên tài nguyên, set lại env vars: `PUBLIC_CONTAINER`, `WIDE_OPEN_SG`, `DEMO_PROJECT`, `DEMO_USER`, `DEMO_ROLE`.
- Xem thêm [docs/HYBRID_SCENARIO_MAPPING.md](./HYBRID_SCENARIO_MAPPING.md) để map 6 kịch bản `AWS -> OpenStack` cho report/demo.
- Sau khi xong phần scan/triage/dashboard, dùng thêm [docs/REMEDIATION.md](./REMEDIATION.md) để:
  - export 3 dashboard thành artifact `.ndjson`
  - chạy runtime remediation demo có audit trail
  - tạo Terraform PR-prep bundle
  - build/publish remediation metrics vào Elasticsearch
- Chạy [docs/TESTING.md](./TESTING.md) để verify scanner normalization, owner notifications, và container secret CI guard.
- Dùng [docs/DELIVERABLES.md](./DELIVERABLES.md) để gom artifact nộp bài và demo evidence.
