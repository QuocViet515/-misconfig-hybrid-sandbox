from src.remediation.drift_reconcile import summarize_plan


def test_summarize_plan_filters_for_m5_security_group():
    plan = {
        "resource_changes": [
            {
                "address": "aws_security_group.m5_intended_sg",
                "change": {
                    "actions": ["update"],
                    "before": {"ingress": [{"from_port": 443}]},
                    "after": {"ingress": [{"from_port": 443}, {"from_port": 22}]},
                },
            },
            {
                "address": "aws_s3_bucket.demo",
                "change": {
                    "actions": ["no-op"],
                    "before": {},
                    "after": {},
                },
            },
        ]
    }

    summary = summarize_plan(plan)

    assert summary["drift_detected"] is True
    assert summary["change_count"] == 1
    assert summary["resource_changes"][0]["address"] == "aws_security_group.m5_intended_sg"
