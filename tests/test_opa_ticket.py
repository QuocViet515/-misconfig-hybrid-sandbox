from src.remediation.opa_ticket import select_iam_wildcard_findings


def test_select_iam_wildcard_findings_requires_actual_wildcard_signal() -> None:
    findings = [
        {
            "provider": "aws",
            "finding_code": "CKV_AWS_SAFE",
            "title": "Scoped IAM policy",
            "description": "Policy is read-only and scoped to a single bucket.",
            "resource_id": "aws_iam_role.demo",
            "metadata": {"file_path": "iac/aws/m3_iam_wildcard.tf"},
        },
        {
            "provider": "aws",
            "finding_code": "IAM_WILDCARD_POLICY",
            "title": "IAM wildcard policy detected",
            "description": "Action * on Resource * creates an IAM wildcard permission.",
            "resource_id": "aws_iam_role.bad",
            "metadata": {"file_path": "iac/aws/m3_iam_wildcard.tf"},
        },
    ]

    selected = select_iam_wildcard_findings(findings)

    assert len(selected) == 1
    assert selected[0]["resource_id"] == "aws_iam_role.bad"
