# OpenStack Event-Driven Post-Deploy Detection

Mục tiêu: khi có thay đổi identity/network sau deploy, OpenStack phát notification qua RabbitMQ; `src.events.openstack_consumer` đọc notification, enrich trạng thái runtime, rồi sinh findings, triage, publish SIEM, và tùy chọn gọi remediation hiện có.

## 1. Bật notification ở control plane

Áp dụng snippet phù hợp vào service config:

- Keystone: `eventing/openstack/keystone_notifications.conf`
- Neutron: `eventing/openstack/neutron_notifications.conf`

Tùy lab, path thực tế thường là:

- `/etc/keystone/keystone.conf`
- `/etc/neutron/neutron.conf`

Sau khi sửa, restart service tương ứng.

## 2. Replay nhanh bằng payload mẫu

```bash
cd /home/deployer/Desktop/-misconfig-hybrid-sandbox
python -m src.events.openstack_consumer \
  --event-file eventing/openstack/samples/admin_role_assignment.json
```

## 3. Chạy consumer trên control node

```bash
cd /home/deployer/Desktop/-misconfig-hybrid-sandbox
python -m src.events.openstack_consumer \
  --rabbitmq-url "amqp://openstack:CHANGE_ME@127.0.0.1:5672/%2F" \
  --rabbitmq-queue notifications \
  --publish-to-siem \
  --build-metrics
```

Nếu muốn execute remediation ngay cho finding đã được approve:

```bash
python -m src.events.openstack_consumer \
  --rabbitmq-url "amqp://openstack:CHANGE_ME@127.0.0.1:5672/%2F" \
  --rabbitmq-queue notifications \
  --publish-to-siem \
  --execute-remediation \
  --approve-finding-id "<FINDING_ID>"
```

## 4. Supported OpenStack detections

- `identity.role_assignment.*`
  - detect user được gán role `admin` trên project
- `security_group_rule.*`
  - detect rule ingress từ `0.0.0.0/0` hoặc `::/0` trên `22`, `3389`, hoặc `all`

## 5. Remediation behavior

- `OPENSTACK_PROJECT_ADMIN_ASSIGNMENT`
  - route sang `openstack role remove`
- `OPENSTACK_SG_WIDE_OPEN`
  - route sang `openstack security group rule delete`

Theo policy hiện tại, các finding severity cao/critical sẽ vào `manual_review` trừ khi bạn approve rõ `finding_id`.
