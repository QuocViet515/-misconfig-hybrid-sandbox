import sys

from src.remediation import metrics
from src.remediation.metrics import build_snapshot


def test_parse_args_collects_repeated_remediation_event_flags(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "metrics.py",
            "--findings",
            "findings.json",
            "--decisions",
            "decisions.json",
            "--remediation-events",
            "aws.json",
            "--remediation-events",
            "openstack.json",
        ],
    )

    args = metrics.parse_args()

    assert args.remediation_events == ["aws.json", "openstack.json"]


def test_build_snapshot_counts_runtime_and_iac_events_separately():
    findings = [
        {
            "finding_id": "f-1",
            "status": "OPEN",
            "cis_controls": ["cis-1"],
            "detected_at": "2026-05-30T00:00:00Z",
        }
    ]
    decisions = [{"finding_id": "f-1", "recommendation": "auto_remediate"}]
    events = [
        {
            "finding_id": "f-1",
            "action_kind": "runtime_remediation",
            "status": "SUCCESS",
            "completed_at": "2026-05-30T00:10:00Z",
        },
        {
            "finding_id": "f-1",
            "action_kind": "iac_pr_prepare",
            "status": "SUCCESS",
        },
    ]

    snapshot = build_snapshot(
        findings,
        decisions,
        events,
        pipeline_source="demo-metrics",
        branch="main",
        commit_sha="abc123",
    )

    assert snapshot.remediation_attempts == 1
    assert snapshot.remediation_successes == 1
    assert snapshot.metadata["iac_pr_prepared_count"] == 1
    assert snapshot.open_findings_after == 0
