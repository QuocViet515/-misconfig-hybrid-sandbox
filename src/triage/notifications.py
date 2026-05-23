"""
Build owner notification and ticket payloads from findings + triage decisions.
"""
from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .engine import load_findings
from ..siem.publisher import load_decisions

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)
HIGH_RISK_SEVERITIES = {"HIGH", "CRITICAL"}


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def resolve_owner(finding) -> str:
    tags = finding.tags or {}
    metadata = finding.metadata or {}
    return (
        tags.get("owner")
        or metadata.get("asset_owner")
        or metadata.get("owner")
        or os.getenv("DEFAULT_SECURITY_OWNER", "security-team@example.com")
    )


def issue_description_lines(finding, decision: Dict[str, Any], owner: str) -> List[str]:
    return [
        f"Owner: {owner}",
        f"Finding ID: {finding.finding_id}",
        f"Finding Code: {finding.finding_code}",
        f"Resource: {finding.resource_type} ({finding.resource_id})",
        f"Provider/Scanner: {finding.provider}/{finding.scanner}",
        f"Severity: {finding.severity}",
        f"Recommendation: {decision.get('recommendation')}",
        f"Reasoning: {decision.get('reasoning')}",
    ]


def build_notifications(findings, decisions: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    findings_by_id = {finding.finding_id: finding for finding in findings}
    bundle: Dict[str, List[Dict[str, Any]]] = {
        "owner_notifications": [],
        "jira_tickets": [],
        "servicenow_incidents": [],
        "chat_notifications": [],
    }

    for decision in decisions:
        if decision.get("recommendation") != "manual_review":
            continue

        finding = findings_by_id.get(str(decision.get("finding_id") or ""))
        if not finding:
            continue

        owner = resolve_owner(finding)
        severity = str(getattr(finding, "severity", "MEDIUM"))
        notification = {
            "finding_id": finding.finding_id,
            "owner": owner,
            "channel": "email",
            "severity": severity,
            "title": finding.title,
            "finding_code": finding.finding_code,
            "scanner": finding.scanner,
            "provider": finding.provider,
            "resource_type": finding.resource_type,
            "resource_id": finding.resource_id,
            "reasoning": decision.get("reasoning"),
            "recommendation": decision.get("recommendation"),
        }
        bundle["owner_notifications"].append(notification)

        if severity not in HIGH_RISK_SEVERITIES:
            continue

        description_lines = issue_description_lines(finding, decision, owner)
        ticket_summary = f"[Security Review] {finding.title}"

        bundle["jira_tickets"].append(
            {
                "summary": ticket_summary,
                "description": "\n".join(description_lines),
                "priority": "Highest" if severity == "CRITICAL" else "High",
                "labels": ["manual-review", "misconfiguration"],
                "owner": owner,
                "project_key": os.getenv("JIRA_PROJECT_KEY", "SEC"),
            }
        )
        bundle["servicenow_incidents"].append(
            {
                "short_description": ticket_summary,
                "description": "\n".join(description_lines),
                "urgency": "1" if severity == "CRITICAL" else "2",
                "impact": "1" if severity == "CRITICAL" else "2",
                "assignment_group": os.getenv("SERVICENOW_ASSIGNMENT_GROUP", "Security Operations"),
                "caller_id": owner,
            }
        )
        bundle["chat_notifications"].append(
            {
                "channel": "slack" if os.getenv("SLACK_WEBHOOK_URL") else "teams" if os.getenv("TEAMS_WEBHOOK_URL") else "chatops",
                "owner": owner,
                "severity": severity,
                "title": finding.title,
                "message": f"{severity} manual review required for {finding.resource_type} {finding.resource_id}",
                "finding_id": finding.finding_id,
            }
        )

    return bundle


def json_request(
    method: str,
    url: str,
    payload: Dict[str, Any],
    *,
    headers: Dict[str, str] | None = None,
    basic_auth: Tuple[str, str] | None = None,
) -> Tuple[int, Dict[str, Any] | str]:
    request_headers = {"Content-Type": "application/json", **(headers or {})}
    if basic_auth is not None:
        username, password = basic_auth
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        request_headers["Authorization"] = f"Basic {token}"

    request = urllib.request.Request(
        url=url,
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.getcode()
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "ignore")
        return exc.code, body
    except urllib.error.URLError as exc:
        return 0, str(exc)

    if not body.strip():
        return status, {}
    try:
        return status, json.loads(body)
    except json.JSONDecodeError:
        return status, body


def jira_adf(text_lines: Iterable[str]) -> Dict[str, Any]:
    content = []
    for line in text_lines:
        content.append(
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": line}],
            }
        )
    return {"type": "doc", "version": 1, "content": content}


def create_jira_issue(ticket: Dict[str, Any]) -> Dict[str, Any]:
    jira_url = os.getenv("JIRA_URL", "").rstrip("/")
    jira_user = os.getenv("JIRA_EMAIL") or os.getenv("JIRA_USERNAME")
    jira_token = os.getenv("JIRA_API_TOKEN") or os.getenv("JIRA_TOKEN")
    if not jira_url or not jira_user or not jira_token:
        raise RuntimeError("JIRA_URL and JIRA_EMAIL/JIRA_USERNAME plus JIRA_API_TOKEN/JIRA_TOKEN are required.")

    payload = {
        "fields": {
            "project": {"key": ticket.get("project_key") or os.getenv("JIRA_PROJECT_KEY", "SEC")},
            "summary": ticket["summary"],
            "description": jira_adf(str(ticket.get("description") or "").splitlines()),
            "issuetype": {"name": os.getenv("JIRA_ISSUE_TYPE", "Task")},
            "labels": ticket.get("labels", []),
            "priority": {"name": ticket.get("priority", "High")},
        }
    }
    status, body = json_request(
        "POST",
        f"{jira_url}/rest/api/3/issue",
        payload,
        headers={"Accept": "application/json"},
        basic_auth=(jira_user, jira_token),
    )
    if status not in {200, 201}:
        raise RuntimeError(f"Jira issue creation failed: {status} {body}")
    return {"status": status, "response": body}


def create_servicenow_incident(ticket: Dict[str, Any]) -> Dict[str, Any]:
    instance_url = os.getenv("SERVICENOW_URL", "").rstrip("/")
    user = os.getenv("SERVICENOW_USER", "")
    password = os.getenv("SERVICENOW_PASSWORD", "")
    table = os.getenv("SERVICENOW_TABLE", "incident")
    if not instance_url or not user or not password:
        raise RuntimeError("SERVICENOW_URL, SERVICENOW_USER, and SERVICENOW_PASSWORD are required.")

    payload: Dict[str, Any] = {
        "short_description": ticket["short_description"],
        "description": ticket.get("description", ""),
        "urgency": ticket.get("urgency", "2"),
        "impact": ticket.get("impact", "2"),
        "category": os.getenv("SERVICENOW_CATEGORY", "security"),
        "subcategory": os.getenv("SERVICENOW_SUBCATEGORY", "misconfiguration"),
    }
    assignment_group = os.getenv("SERVICENOW_ASSIGNMENT_GROUP_SYS_ID") or ticket.get("assignment_group")
    caller_id = os.getenv("SERVICENOW_CALLER_SYS_ID") or ticket.get("caller_id")
    if assignment_group:
        payload["assignment_group"] = assignment_group
    if caller_id:
        payload["caller_id"] = caller_id

    status, body = json_request(
        "POST",
        f"{instance_url}/api/now/table/{table}",
        payload,
        headers={"Accept": "application/json"},
        basic_auth=(user, password),
    )
    if status not in {200, 201}:
        raise RuntimeError(f"ServiceNow incident creation failed: {status} {body}")
    return {"status": status, "response": body}


def send_slack_message(notification: Dict[str, Any]) -> Dict[str, Any]:
    webhook = os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook:
        raise RuntimeError("SLACK_WEBHOOK_URL is required.")

    text = (
        f"[{notification['severity']}] Manual review required: {notification['title']} "
        f"({notification['resource_type']} {notification['resource_id']})"
    )
    payload = {
        "text": text,
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{notification['severity']}* manual review required"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Finding*\n{notification['title']}"},
                    {"type": "mrkdwn", "text": f"*Owner*\n{notification['owner']}"},
                    {"type": "mrkdwn", "text": f"*Resource*\n{notification['resource_id']}"},
                    {"type": "mrkdwn", "text": f"*Source*\n{notification['provider']}/{notification['scanner']}"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": notification.get("reasoning", "Manual review required")},
            },
        ],
    }
    status, body = json_request("POST", webhook, payload)
    if status not in {200, 201}:
        raise RuntimeError(f"Slack notification failed: {status} {body}")
    return {"status": status, "response": body}


def send_teams_message(notification: Dict[str, Any]) -> Dict[str, Any]:
    webhook = os.getenv("TEAMS_WEBHOOK_URL", "")
    if not webhook:
        raise RuntimeError("TEAMS_WEBHOOK_URL is required.")

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": "Security Manual Review Required"},
                        {"type": "TextBlock", "text": f"Severity: {notification['severity']}", "wrap": True},
                        {"type": "TextBlock", "text": notification["title"], "wrap": True},
                        {"type": "FactSet", "facts": [
                            {"title": "Owner", "value": notification["owner"]},
                            {"title": "Resource", "value": notification["resource_id"]},
                            {"title": "Source", "value": f"{notification['provider']}/{notification['scanner']}"},
                        ]},
                        {"type": "TextBlock", "text": notification.get("reasoning", "Manual review required"), "wrap": True},
                    ],
                },
            }
        ],
    }
    status, body = json_request("POST", webhook, payload)
    if status not in {200, 201, 202}:
        raise RuntimeError(f"Teams notification failed: {status} {body}")
    return {"status": status, "response": body}


def dispatch_live_integrations(bundle: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    results: Dict[str, List[Dict[str, Any]]] = {
        "jira": [],
        "servicenow": [],
        "slack": [],
        "teams": [],
        "errors": [],
    }

    for ticket in bundle["jira_tickets"]:
        try:
            results["jira"].append({"summary": ticket["summary"], **create_jira_issue(ticket)})
        except Exception as exc:
            results["errors"].append({"channel": "jira", "summary": ticket["summary"], "error": str(exc)})

    for incident in bundle["servicenow_incidents"]:
        try:
            results["servicenow"].append(
                {"short_description": incident["short_description"], **create_servicenow_incident(incident)}
            )
        except Exception as exc:
            results["errors"].append(
                {"channel": "servicenow", "short_description": incident["short_description"], "error": str(exc)}
            )

    for notification in bundle["chat_notifications"]:
        if os.getenv("SLACK_WEBHOOK_URL"):
            try:
                results["slack"].append({"finding_id": notification["finding_id"], **send_slack_message(notification)})
            except Exception as exc:
                results["errors"].append({"channel": "slack", "finding_id": notification["finding_id"], "error": str(exc)})
        if os.getenv("TEAMS_WEBHOOK_URL"):
            try:
                results["teams"].append({"finding_id": notification["finding_id"], **send_teams_message(notification)})
            except Exception as exc:
                results["errors"].append({"channel": "teams", "finding_id": notification["finding_id"], "error": str(exc)})

    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build triage notification artifacts")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--output-dir", default="artifacts/triage_notifications")
    parser.add_argument("--dispatch-live", action="store_true", help="Send live notifications to configured integrations")
    parser.add_argument("--fail-on-dispatch-error", action="store_true", help="Exit non-zero if a live integration call fails")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings)
    decisions = load_decisions(args.decisions)
    bundle = build_notifications(findings, decisions)

    output_dir = Path(args.output_dir)
    for filename, payload in (
        ("owner_notifications.json", bundle["owner_notifications"]),
        ("jira_tickets.json", bundle["jira_tickets"]),
        ("servicenow_incidents.json", bundle["servicenow_incidents"]),
        ("chat_notifications.json", bundle["chat_notifications"]),
    ):
        save_json(output_dir / filename, payload)
    logger.info(
        "Generated %s owner notifications, %s JIRA payloads, %s ServiceNow payloads, and %s chat notifications",
        len(bundle["owner_notifications"]),
        len(bundle["jira_tickets"]),
        len(bundle["servicenow_incidents"]),
        len(bundle["chat_notifications"]),
    )
    if args.dispatch_live:
        results = dispatch_live_integrations(bundle)
        save_json(output_dir / "dispatch_results.json", results)
        logger.info(
            "Dispatched live integrations: jira=%s servicenow=%s slack=%s teams=%s errors=%s",
            len(results["jira"]),
            len(results["servicenow"]),
            len(results["slack"]),
            len(results["teams"]),
            len(results["errors"]),
        )
        if args.fail_on_dispatch_error and results["errors"]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
