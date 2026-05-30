from src.events.aws_consumer import (
    make_iam_finding,
    make_s3_finding,
    make_sg_finding,
    policy_document_has_wildcards,
    risky_sg_permissions,
    s3_public_violation,
)


def sample_event(name: str) -> dict:
    return {
        "id": f"evt-{name}",
        "time": "2026-05-30T02:15:00Z",
        "detail-type": "AWS API Call via CloudTrail",
        "region": "ap-southeast-1",
        "detail": {
            "eventID": f"cloudtrail-{name}",
            "eventName": name,
            "eventSource": "ec2.amazonaws.com",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/demo"},
            "sourceIPAddress": "203.0.113.10",
        },
    }


def test_risky_sg_permissions_detects_world_open_ssh():
    security_group = {
        "GroupId": "sg-123",
        "GroupName": "demo-sg",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            }
        ],
    }

    matches = risky_sg_permissions(security_group)

    assert matches == [{"protocol": "tcp", "port_range": "22", "networks": ["0.0.0.0/0"]}]


def test_s3_public_violation_detects_disabled_public_blocks():
    bucket_state = {
        "bucket_name": "demo-bucket",
        "public_access_block": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": True,
        },
        "policy_status": {"IsPublic": False},
        "acl_grants": [],
    }

    assert s3_public_violation(bucket_state) is True


def test_policy_document_has_wildcards_detects_star_action_and_resource():
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }

    assert policy_document_has_wildcards(document) is True


def test_make_sg_finding_routes_to_existing_runtime_flow():
    event = sample_event("AuthorizeSecurityGroupIngress")
    security_group = {"GroupId": "sg-123", "GroupName": "demo-sg"}
    finding = make_sg_finding(
        event,
        security_group,
        [{"protocol": "tcp", "port_range": "22", "networks": ["0.0.0.0/0"]}],
    )

    assert finding.finding_code == "AWS_EVENT_OPEN_SECURITY_GROUP"
    assert finding.metadata["file_path"] == "iac/aws/m2_wide_open_sg.tf"
    assert finding.remediation_available is True
    assert finding.remediation_type == "ansible"


def test_make_s3_finding_routes_to_existing_runtime_flow():
    event = sample_event("PutBucketPolicy")
    bucket_state = {
        "bucket_name": "demo-bucket",
        "public_access_block": {},
        "policy_status": {"IsPublic": True},
        "acl_grants": [],
    }

    finding = make_s3_finding(event, bucket_state)

    assert finding.finding_code == "AWS_EVENT_PUBLIC_S3"
    assert finding.metadata["file_path"] == "iac/aws/m1_public_s3.tf"
    assert finding.remediation_type == "cloud_custodian"


def test_make_iam_finding_stays_manual_review_only():
    event = sample_event("AttachRolePolicy")
    finding = make_iam_finding(
        event,
        resource_type="aws_iam_role",
        resource_name="demo-role",
        policy_refs=["arn:aws:iam::123456789012:policy/AdminEverywhere"],
    )

    assert finding.finding_code == "AWS_EVENT_IAM_WILDCARD"
    assert finding.remediation_available is False
    assert finding.remediation_type == "manual"

