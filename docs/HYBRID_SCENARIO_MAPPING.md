# Hybrid Scenario Mapping

Tài liệu này map 6 kịch bản misconfiguration của `AWS lab` sang `OpenStack lab` để dùng thống nhất trong:

- report capstone
- demo script
- phần giải thích vì sao project được gọi là `hybrid cloud`

## 1) Nguyên tắc mapping

Không phải mọi dịch vụ AWS đều có bản sao `1:1` trên OpenStack. Vì vậy bộ mapping được chia thành 3 nhóm:

1. `Direct equivalent`
   - có dịch vụ và hành vi gần như tương đương giữa AWS và OpenStack
2. `Platform-adapted equivalent`
   - cùng loại rủi ro, nhưng cách triển khai/phát hiện khác nhau theo platform
3. `Cloud-agnostic control`
   - bản chất nằm ở IaC / container / CI pipeline, không phụ thuộc riêng AWS hay OpenStack

## 2) Mapping 6 kịch bản

| ID | AWS scenario | OpenStack equivalent | Mapping type | Repo status |
| --- | --- | --- | --- | --- |
| `M1` | Public `S3` bucket / policy / ACL | Public `Swift` container (`.r:*,.rlistings`) | Direct equivalent | Implemented |
| `M2` | Wide-open `Security Group` | Wide-open `Neutron Security Group` | Direct equivalent | Implemented |
| `M3` | Over-privileged `IAM` policy / principal | Over-privileged `Keystone` role assignment (`admin` on project) | Direct equivalent | Implemented |
| `M4` | Unencrypted `EBS` / `Snapshot` / `S3` / `RDS` | Unencrypted `Cinder volume` / `snapshot` / object storage at-rest policy gaps | Platform-adapted equivalent | Design only |
| `M5` | `Terraform` drift on AWS SG | `Terraform/OpenTofu` drift on Neutron SG or Swift ACL | Platform-adapted equivalent | Design only |
| `M6` | Container secret in `Dockerfile` / ECS path | Same container/image/CI issue, independent of cloud | Cloud-agnostic control | Implemented once for both |

## 3) Chi tiết từng scenario

### M1: Public object storage

**AWS**
- Misconfig: `S3` bucket public qua ACL hoặc bucket policy
- Evidence:
  - `ScoutSuite`
  - `CloudSploit`
  - `Checkov` / `tfsec` / `Trivy` nếu xét từ IaC

**OpenStack**
- Misconfig: `Swift` container public read/listing
- Evidence:
  - `openstack container show <container> -f json`
  - normalize thành `OPENSTACK_SWIFT_PUBLIC_READ`

**Report wording**
- `M1 demonstrates equivalent public object storage exposure across AWS S3 and OpenStack Swift.`

**Repo status**
- AWS: implemented
- OpenStack: implemented

### M2: Wide-open network perimeter

**AWS**
- Misconfig: `Security Group` mở `22`, `3389`, hoặc `all traffic` ra `0.0.0.0/0`

**OpenStack**
- Misconfig: `Neutron Security Group` mở cùng kiểu ingress ra Internet
- Evidence:
  - `openstack security group rule list <sg> -f json`
  - normalize thành `OPENSTACK_SG_WIDE_OPEN`

**Report wording**
- `M2 shows that overly permissive east-west and north-south ingress rules are portable risks across cloud providers.`

**Repo status**
- AWS: implemented
- OpenStack: implemented

### M3: Over-privileged identity

**AWS**
- Misconfig: wildcard `IAM` permissions hoặc admin-like access path

**OpenStack**
- Misconfig: `Keystone` user được gán role `admin` trên project demo
- Evidence:
  - `openstack role assignment list --names -f json`
  - normalize thành `OPENSTACK_PROJECT_ADMIN_ASSIGNMENT`

**Report wording**
- `M3 maps excessive privileges from AWS IAM to OpenStack Keystone by expressing the same control failure through project-level administrative assignment.`

**Repo status**
- AWS: implemented
- OpenStack: implemented

### M4: Unencrypted storage

**AWS**
- Misconfig:
  - unencrypted `EBS volume`
  - unencrypted `snapshot`
  - `S3` without server-side encryption
  - unencrypted `RDS`

**OpenStack equivalent**
- `Cinder` volume không dùng encrypted volume type
- `Cinder` snapshot / backend storage không enforce encryption
- object storage không có chính sách at-rest encryption ở tầng platform/backend

**Lưu ý kỹ thuật**
- Đây không phải mapping `1:1`.
- OpenStack encryption-at-rest phụ thuộc:
  - `Cinder volume type encryption`
  - backend storage capability
  - cách cloud operator cấu hình KMS / Barbican / backend driver

**Recommended demo design**
- Tạo một `Cinder` volume type không encryption làm baseline insecure
- Provision volume demo từ type này
- Export evidence bằng:
  - `openstack volume show`
  - `openstack volume type show`
- Normalize thành finding kiểu `OPENSTACK_CINDER_UNENCRYPTED`

**Report wording**
- `M4 is a platform-adapted storage encryption scenario: AWS exposes the issue at service level, while OpenStack expresses it through Cinder volume type and backend encryption posture.`

**Repo status**
- AWS: implemented
- OpenStack: design only

### M5: IaC drift

**AWS**
- Misconfig: resource được deploy từ Terraform, sau đó bị sửa tay ngoài IaC
- Repo hiện dùng `aws_security_group.m5_intended_sg`

**OpenStack equivalent**
- Deploy `Neutron Security Group` hoặc `Swift ACL` bằng `Terraform OpenStack provider`
- Sau đó sửa tay bằng `openstack` CLI
- Chạy `terraform plan` để phát hiện drift

**Recommended demo design**
- Baseline:
  - SG chỉ cho `443` nội bộ
- Tạo drift:
  - thêm `22/tcp` từ `0.0.0.0/0`
- Detect:
  - `terraform plan -detailed-exitcode`
- Reconcile:
  - `terraform apply`

**Report wording**
- `M5 is modeled consistently across providers as an infrastructure drift problem: the runtime state diverges from the declarative baseline and is then reconciled through Terraform.`

**Repo status**
- AWS: implemented end-to-end
- OpenStack: design only

### M6: Container secret exposure

**AWS**
- Misconfig: credentials/secrets bị hardcode trong `Dockerfile`, container build path, hoặc task definition workflow

**OpenStack equivalent**
- Đây không phải lỗi riêng AWS.
- Nó là lỗi của:
  - source repo
  - container image build
  - CI/CD pipeline
- Nếu workload deploy trên OpenStack, cùng một image lỗi vẫn gây impact y hệt.

**Recommended positioning**
- Không ép map sang dịch vụ OpenStack cụ thể.
- Trình bày đây là `cloud-agnostic control` áp cho mọi cloud target.

**Report wording**
- `M6 is intentionally modeled as a cloud-agnostic pipeline control rather than a provider-specific runtime misconfiguration.`

**Repo status**
- Implemented once and reused for both AWS/OpenStack delivery paths

## 4) Coverage statement cho report

Bạn có thể dùng nguyên văn đoạn này:

> The capstone implements a hybrid cloud security pipeline by combining AWS-native misconfiguration scenarios with OpenStack-equivalent scenarios where direct service parity exists, and by using platform-adapted or cloud-agnostic controls where exact parity does not exist. Direct equivalence was achieved for object storage exposure, network perimeter exposure, and identity over-privilege. Storage encryption and IaC drift were modeled as platform-adapted scenarios, while container secret exposure was treated as a cloud-agnostic CI/CD control.

## 5) Demo statement ngắn

Nếu cần nói ngắn khi demo:

1. `M1-M3` là phần hybrid rõ nhất vì AWS và OpenStack có equivalent trực tiếp.
2. `M4-M5` là equivalent theo loại rủi ro, không phải theo đúng tên dịch vụ.
3. `M6` nằm ở CI/container layer nên dùng chung cho cả hai cloud.

## 6) Recommended scope cho đồ án hiện tại

Nếu muốn giữ demo gọn nhưng vẫn thuyết phục:

- `AWS`: trình diễn đủ `M1-M6`
- `OpenStack`: trình diễn chắc `M1-M3`
- `Report`: mô tả `M4-M5` như phần mở rộng hybrid tiếp theo
- `M6`: giải thích là control chung cho mọi target cloud

Đây là cách vừa trung thực với trạng thái repo, vừa giữ được lập luận `hybrid cloud` chặt chẽ.
