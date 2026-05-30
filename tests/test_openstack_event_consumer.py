from src.events.openstack_consumer import (
    make_role_assignment_finding,
    make_sg_rule_finding,
    wide_open_rule,
)


def sample_event(kind: str) -> dict:
    return {
        "event_id": f"evt-{kind}",
        "timestamp": "2026-05-30T02:15:00Z",
        "event_type": kind,
    }


def test_wide_open_rule_detects_ingress_from_anywhere():
    context = {
        "rule_id": "rule-1",
        "direction": "ingress",
        "remote_ip": "0.0.0.0/0",
        "protocol": "tcp",
        "port_range": "22",
    }

    assert wide_open_rule(context) is True


def test_make_role_assignment_finding_matches_existing_code():
    event = sample_event("identity.role_assignment.created")
    context = {
        "role_name": "admin",
        "role_id": "role-1",
        "user_name": "demo-user",
        "user_id": "user-1",
        "project_name": "demo-project",
        "project_id": "proj-1",
    }

    finding = make_role_assignment_finding(event, context)

    assert finding.finding_code == "OPENSTACK_PROJECT_ADMIN_ASSIGNMENT"
    assert finding.severity == "CRITICAL"
    assert finding.metadata["file_path"] == "iac/openstack/m3_identity_overprivilege.tf"


def test_make_sg_rule_finding_matches_existing_code():
    event = sample_event("security_group_rule.create.end")
    context = {
        "rule_id": "rule-1",
        "security_group_id": "sg-1",
        "security_group_name": "demo-sg",
        "direction": "ingress",
        "remote_ip": "0.0.0.0/0",
        "protocol": "tcp",
        "port_range": "22",
    }

    finding = make_sg_rule_finding(event, context)

    assert finding.finding_code == "OPENSTACK_SG_WIDE_OPEN"
    assert finding.resource_id == "rule-1"
    assert finding.metadata["security_group_id"] == "sg-1"
