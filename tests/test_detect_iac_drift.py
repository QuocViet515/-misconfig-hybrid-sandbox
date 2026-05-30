from pathlib import Path

import pytest

from src.remediation.detect_iac_drift import build_findings, ensure_local_state, summarize_changes


def test_summarize_changes_ignores_no_op_entries():
    plan = {
        "resource_changes": [
            {
                "address": "aws_security_group.demo",
                "type": "aws_security_group",
                "change": {
                    "actions": ["update"],
                    "before": {"ingress": []},
                    "after": {"ingress": [{"from_port": 22}]},
                },
            },
            {
                "address": "aws_s3_bucket.noop",
                "type": "aws_s3_bucket",
                "change": {
                    "actions": ["no-op"],
                    "before": {},
                    "after": {},
                },
            },
        ]
    }

    summary = summarize_changes(plan)

    assert summary["drift_detected"] is True
    assert summary["change_count"] == 1
    assert summary["by_action"] == {"update": 1}
    assert summary["resource_changes"][0]["address"] == "aws_security_group.demo"


def test_build_findings_creates_manual_drift_finding():
    summary = {
        "resource_changes": [
            {
                "address": "openstack_networking_secgroup_v2.demo",
                "resource_type": "openstack_networking_secgroup_v2",
                "actions": ["update"],
                "before": {"name": "before"},
                "after": {"name": "after"},
            }
        ]
    }

    findings = build_findings(
        provider="openstack",
        stack_name="openstack",
        region="",
        plan_summary=summary,
    )

    assert len(findings) == 1
    assert findings[0]["finding_code"] == "IAC_DRIFT_DETECTED"
    assert findings[0]["provider"] == "openstack"
    assert findings[0]["remediation_available"] is False
    assert findings[0]["remediation_type"] == "manual"


def test_ensure_local_state_writes_summary_before_failing(tmp_path: Path):
    terraform_dir = tmp_path / "iac" / "aws"
    terraform_dir.mkdir(parents=True)
    output_dir = tmp_path / "artifacts"

    with pytest.raises(RuntimeError, match="No local terraform.tfstate was restored"):
        ensure_local_state(terraform_dir, output_dir, "aws", "aws")

    summary_path = output_dir / "summary.json"
    assert summary_path.exists()
    assert '"state_present": false' in summary_path.read_text(encoding="utf-8")
