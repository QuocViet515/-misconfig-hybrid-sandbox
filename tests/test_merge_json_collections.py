from scripts.merge_json_collections import deduplicate_findings


def test_deduplicate_findings_keeps_one_record_for_same_issue_on_same_asset():
    findings = [
        {
            "finding_id": "a",
            "provider": "aws",
            "resource_type": "s3_bucket",
            "resource_id": "demo-bucket",
            "resource_name": "demo-bucket",
            "finding_code": "PUBLIC_BUCKET",
            "title": "Bucket is public",
            "severity": "HIGH",
            "metadata": {"path": "iac/aws/m1_public_s3.tf"},
            "scanner": "checkov",
        },
        {
            "finding_id": "b",
            "provider": "aws",
            "resource_type": "s3_bucket",
            "resource_id": "demo-bucket",
            "resource_name": "demo-bucket",
            "finding_code": "PUBLIC_BUCKET",
            "title": "Bucket is public",
            "severity": "HIGH",
            "metadata": {"path": "iac/aws/m1_public_s3.tf"},
            "scanner": "tfsec",
        },
    ]

    deduped = deduplicate_findings(findings)

    assert len(deduped) == 1
    assert deduped[0]["finding_id"] == "a"


def test_deduplicate_findings_preserves_distinct_rule_variants():
    findings = [
        {
            "finding_id": "ssh",
            "provider": "openstack",
            "resource_type": "security_group_rule",
            "resource_id": "rule-ssh",
            "resource_name": "wide-open-sg",
            "finding_code": "OPENSTACK_SG_WIDE_OPEN",
            "title": "OpenStack security group allows inbound access from anywhere",
            "severity": "HIGH",
            "metadata": {"port_range": "22:22", "remote_ip": "0.0.0.0/0"},
        },
        {
            "finding_id": "rdp",
            "provider": "openstack",
            "resource_type": "security_group_rule",
            "resource_id": "rule-rdp",
            "resource_name": "wide-open-sg",
            "finding_code": "OPENSTACK_SG_WIDE_OPEN",
            "title": "OpenStack security group allows inbound access from anywhere",
            "severity": "HIGH",
            "metadata": {"port_range": "3389:3389", "remote_ip": "0.0.0.0/0"},
        },
    ]

    deduped = deduplicate_findings(findings)

    assert len(deduped) == 2
