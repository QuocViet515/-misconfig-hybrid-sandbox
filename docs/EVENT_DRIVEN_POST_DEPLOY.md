# Event-Driven Post-Deployment Detection

Repo hiện có thêm hai consumer cho post-deployment detection kiểu event-driven:

- `python -m src.events.aws_consumer`
- `python -m src.events.openstack_consumer`

Luồng chung:

1. cloud phát event thay đổi cấu hình
2. consumer nhận event
3. consumer enrich trạng thái runtime hiện tại bằng API/CLI
4. nếu có vi phạm thì tạo `NormalizedFinding`
5. findings đi qua `TriageEngine`
6. findings/decisions được publish lên Elasticsearch
7. nếu bật runtime remediation, consumer gọi lại executor hiện có của repo

## AWS

- Provision rule + queue: [eventing/aws/terraform](../eventing/aws/terraform)
- Consumer docs: [eventing/aws/README.md](../eventing/aws/README.md)

## OpenStack

- Notification snippets: [eventing/openstack](../eventing/openstack)
- Consumer docs: [eventing/openstack/README.md](../eventing/openstack/README.md)

## Khi nào nên dùng

- muốn phát hiện nhanh thay đổi tay trên cloud thật
- không muốn chờ full runtime scan định kỳ
- muốn bám sát đúng vai trò `post-deployment` trong file MD: detect runtime drift và route sang remediation/manual review

## Khi nào vẫn giữ scheduled scan

- resource/service không phát notification đầy đủ
- cần full-account/full-project baseline scan
- muốn có lớp backup nếu event bus hoặc queue bị gián đoạn

