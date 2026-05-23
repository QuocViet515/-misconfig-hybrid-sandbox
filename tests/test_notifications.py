from src.models import NormalizedFinding
from src.triage.notifications import build_notifications, dispatch_live_integrations, jira_adf


def test_build_notifications_creates_owner_alerts_and_high_risk_tickets(monkeypatch):
    monkeypatch.setenv("DEFAULT_SECURITY_OWNER", "sec-owner@example.com")

    findings = [
        NormalizedFinding(
            finding_id="f-1",
            finding_code="CKV_AWS_20",
            scanner="checkov",
            provider="aws",
            severity="CRITICAL",
            title="Critical bucket finding",
            description="Critical issue",
            resource_type="terraform_resource",
            resource_id="aws_s3_bucket.demo",
            metadata={"asset_owner": "cloud-owner@example.com"},
        ),
        NormalizedFinding(
            finding_id="f-2",
            finding_code="CKV_AWS_8",
            scanner="checkov",
            provider="aws",
            severity="LOW",
            title="Low severity finding",
            description="Low issue",
            resource_type="terraform_resource",
            resource_id="aws_security_group.demo",
        ),
    ]
    decisions = [
        {"finding_id": "f-1", "recommendation": "manual_review", "reasoning": "high risk"},
        {"finding_id": "f-2", "recommendation": "manual_review", "reasoning": "needs owner ack"},
        {"finding_id": "f-3", "recommendation": "auto_remediate", "reasoning": "ignored here"},
    ]

    bundle = build_notifications(findings, decisions)

    assert len(bundle["owner_notifications"]) == 2
    assert bundle["owner_notifications"][0]["owner"] == "cloud-owner@example.com"
    assert len(bundle["jira_tickets"]) == 1
    assert len(bundle["servicenow_incidents"]) == 1
    assert len(bundle["chat_notifications"]) == 1
    assert bundle["jira_tickets"][0]["priority"] == "Highest"
    assert bundle["servicenow_incidents"][0]["caller_id"] == "cloud-owner@example.com"


def test_jira_adf_builds_document():
    payload = jira_adf(["line one", "line two"])

    assert payload["type"] == "doc"
    assert payload["version"] == 1
    assert len(payload["content"]) == 2
    assert payload["content"][0]["content"][0]["text"] == "line one"


def test_dispatch_live_integrations_routes_all_channels(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://slack.example.test")
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://teams.example.test")

    calls = []

    def fake_jira(ticket):
        calls.append(("jira", ticket["summary"]))
        return {"status": 201, "response": {"key": "SEC-1"}}

    def fake_servicenow(ticket):
        calls.append(("servicenow", ticket["short_description"]))
        return {"status": 201, "response": {"result": {"number": "INC001"}}}

    def fake_slack(notification):
        calls.append(("slack", notification["finding_id"]))
        return {"status": 200, "response": "ok"}

    def fake_teams(notification):
        calls.append(("teams", notification["finding_id"]))
        return {"status": 202, "response": "accepted"}

    monkeypatch.setattr("src.triage.notifications.create_jira_issue", fake_jira)
    monkeypatch.setattr("src.triage.notifications.create_servicenow_incident", fake_servicenow)
    monkeypatch.setattr("src.triage.notifications.send_slack_message", fake_slack)
    monkeypatch.setattr("src.triage.notifications.send_teams_message", fake_teams)

    bundle = {
        "jira_tickets": [{"summary": "Jira summary"}],
        "servicenow_incidents": [{"short_description": "SN summary"}],
        "chat_notifications": [{"finding_id": "f-1"}],
    }
    results = dispatch_live_integrations(bundle)

    assert results["errors"] == []
    assert len(results["jira"]) == 1
    assert len(results["servicenow"]) == 1
    assert len(results["slack"]) == 1
    assert len(results["teams"]) == 1
    assert calls == [
        ("jira", "Jira summary"),
        ("servicenow", "SN summary"),
        ("slack", "f-1"),
        ("teams", "f-1"),
    ]
