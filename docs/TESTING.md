# Testing Guide

Repo này đã có test suite tối thiểu cho các phần bị trừ điểm trong rubric:

- `tfsec` normalization
- `Trivy` misconfiguration + secret normalization
- triage owner/ticket notification artifacts
- live notification dispatch fan-out
- container secret CI guard
- M5 drift plan summarization

## 1) Cài test dependencies

```bash
python3 -m venv .venv
./.venv/bin/pip install -r requirements.txt
./.venv/bin/pip install -r requirements-dev.txt
```

## 2) Chạy unit tests

```bash
./.venv/bin/python -m pytest tests
```

## 3) Scope hiện tại

- `tests/test_tfsec_scanner.py`
- `tests/test_trivy_scanner.py`
- `tests/test_notifications.py`
- `tests/test_drift_reconcile.py`
- `tests/test_scan_container_secrets.py`
- `tests/test_merge_json_collections.py`
- `tests/test_openstack_findings.py`

## 4) CI coverage

Các workflow chính hiện chạy `pytest` trước scanner/remediation:

- `.github/workflows/hybrid_runtime_scan.yml`
- `.github/workflows/iac_scan.yml`
- `.github/workflows/hybrid_delivery_pipeline.yml`
- `.github/workflows/detect_iac_drift.yml`

Điều này giúp fail sớm nếu:

- schema normalize của scanner mới bị lệch
- triage notification artifacts đổi format
- live integration payload routing bị regression
- drift reconciliation summary bị lệch khỏi Terraform plan
- rule block container secret bị regression

## 5) IaC drift detection

Workflow `.github/workflows/detect_iac_drift.yml` dùng:

- `terraform plan -refresh-only -detailed-exitcode`
- state snapshot được lưu bền trên self-hosted runner qua `scripts/sync_terraform_state.sh`

Điều này cho phép phát hiện drift giữa:

- desired state trong `iac/aws` hoặc `iac/openstack`
- state Terraform đã lưu
- runtime state thật trên cloud

Lưu ý:

- workflow drift sẽ fail rõ ràng nếu runner chưa restore được `terraform.tfstate` cho stack tương ứng
- state snapshot hiện được lưu sau bước deploy trong workflow `.github/workflows/hybrid_delivery_pipeline.yml`
