"""
Consume OpenStack notifications, enrich current runtime state, and emit normalized findings.
"""
from __future__ import annotations

import argparse
import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from uuid import NAMESPACE_URL, uuid5

from ..models import NormalizedFinding, SeverityLevel
from .common import (
    ARTIFACTS_ROOT,
    build_metrics,
    finding_dicts,
    publish_to_siem,
    run_runtime_remediation,
    save_json,
    triage_findings,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def utc_from_event(raw: Any) -> datetime:
    if raw in (None, ""):
        return datetime.now(timezone.utc).replace(microsecond=0)
    text = str(raw).replace("Z", "+00:00")
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(timezone.utc).replace(microsecond=0)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def stable_uuid(seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"openstack-event-consumer:{seed}"))


def run_openstack_json(command: List[str]) -> Any:
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Command failed: {' '.join(command)}")
    return json.loads(result.stdout or "{}")


def load_event_payloads(paths: Sequence[str]) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    for path in paths:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(raw, list):
            payloads.extend(item for item in raw if isinstance(item, dict))
        elif isinstance(raw, dict):
            payloads.append(raw)
    return payloads


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    if "oslo.message" in event and isinstance(event.get("oslo.message"), str):
        try:
            inner = json.loads(str(event["oslo.message"]))
        except json.JSONDecodeError:
            return event
        if isinstance(inner, dict):
            return inner
    return event


def consume_rabbitmq_messages(
    *,
    amqp_url: str,
    queue: str,
    max_messages: int,
    ack_consumed: bool,
    exchange: str,
    routing_key: str,
    declare_queue: bool,
    durable_queue: bool,
) -> List[Dict[str, Any]]:
    try:
        import pika  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only when dependency missing
        raise RuntimeError("pika is required for RabbitMQ consumption. Install dependencies from requirements.txt.") from exc

    payloads: List[Dict[str, Any]] = []
    connection = pika.BlockingConnection(pika.URLParameters(amqp_url))
    try:
        channel = connection.channel()
        if declare_queue:
            channel.queue_declare(queue=queue, durable=durable_queue)
            channel.queue_bind(queue=queue, exchange=exchange, routing_key=routing_key)
        for _ in range(max_messages):
            method_frame, _, body = channel.basic_get(queue=queue, auto_ack=False)
            if method_frame is None:
                break
            try:
                payload = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                if ack_consumed:
                    channel.basic_ack(method_frame.delivery_tag)
                continue
            if isinstance(payload, dict):
                payloads.append(payload)
            if ack_consumed:
                channel.basic_ack(method_frame.delivery_tag)
    finally:
        connection.close()
    return payloads


def event_type(event: Dict[str, Any]) -> str:
    event = normalize_event(event)
    return str(
        event.get("event_type")
        or event.get("eventType")
        or event.get("type")
        or event.get("action")
        or ""
    )


def event_id(event: Dict[str, Any]) -> str:
    event = normalize_event(event)
    return str(event.get("message_id") or event.get("event_id") or event.get("id") or stable_uuid(json.dumps(event, sort_keys=True)))


def event_time(event: Dict[str, Any]) -> datetime:
    event = normalize_event(event)
    payload = get_payload(event)
    return utc_from_event(
        event.get("timestamp")
        or event.get("generated")
        or event.get("time")
        or payload.get("timestamp")
        or payload.get("eventTime")
    )


def get_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    event = normalize_event(event)
    payload = event.get("payload")
    return payload if isinstance(payload, dict) else event


def get_first(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def is_role_assignment_event(event: Dict[str, Any]) -> bool:
    kind = event_type(event).lower()
    return any(token in kind for token in ("role_assignment", "role assignment"))


def is_security_group_rule_event(event: Dict[str, Any]) -> bool:
    kind = event_type(event).lower()
    return "security_group_rule" in kind or "security group rule" in kind


def resolve_role_assignment_context(event: Dict[str, Any]) -> Dict[str, str]:
    payload = get_payload(event)
    role_name = str(get_first(payload, "role_name", "role", "roleName", "Role") or "")
    role_id = str(get_first(payload, "role_id", "roleId") or "")
    user_name = str(get_first(payload, "user_name", "user", "userName", "User") or "")
    user_id = str(get_first(payload, "user_id", "userId") or "")
    project_name = str(get_first(payload, "project_name", "project", "projectName", "Project") or "")
    project_id = str(get_first(payload, "project_id", "projectId") or "")

    if len(role_name) == 32 and not role_id:
        role_id, role_name = role_name, ""
    if len(user_name) == 32 and not user_id:
        user_id, user_name = user_name, ""
    if len(project_name) == 32 and not project_id:
        project_id, project_name = project_name, ""

    if role_id and not role_name:
        role_name = str(run_openstack_json(["openstack", "role", "show", role_id, "-f", "json"]).get("name") or "")
    if user_id and not user_name:
        user_name = str(run_openstack_json(["openstack", "user", "show", user_id, "-f", "json"]).get("name") or "")
    if project_id and not project_name:
        project_name = str(run_openstack_json(["openstack", "project", "show", project_id, "-f", "json"]).get("name") or "")
    if user_name and not user_id:
        user_id = str(run_openstack_json(["openstack", "user", "show", user_name, "-f", "json"]).get("id") or "")
    if project_name and not project_id:
        project_id = str(run_openstack_json(["openstack", "project", "show", project_name, "-f", "json"]).get("id") or "")
    if role_name and not role_id:
        role_id = str(run_openstack_json(["openstack", "role", "show", role_name, "-f", "json"]).get("id") or "")

    return {
        "role_name": role_name,
        "role_id": role_id,
        "user_name": user_name,
        "user_id": user_id,
        "project_name": project_name,
        "project_id": project_id,
    }


def role_assignment_still_exists(context: Dict[str, str]) -> bool:
    rows = run_openstack_json(
        [
            "openstack",
            "role",
            "assignment",
            "list",
            "--project",
            context["project_id"] or context["project_name"],
            "--user",
            context["user_id"] or context["user_name"],
            "-f",
            "json",
        ]
    )
    for row in rows if isinstance(rows, list) else []:
        role_value = str(get_first(row, "Role", "role") or "")
        if context["role_id"] and role_value == context["role_id"]:
            return True
        if context["role_name"] and context["role_name"].lower() in role_value.lower():
            return True
    return False


def make_role_assignment_finding(event: Dict[str, Any], context: Dict[str, str]) -> NormalizedFinding:
    detected_at = event_time(event)
    role_name = context["role_name"] or "admin"
    project_name = context["project_name"] or context["project_id"] or "unknown-project"
    user_name = context["user_name"] or context["user_id"] or "unknown-user"
    resource_id = f"{project_name}:{user_name}:{role_name}"
    return NormalizedFinding(
        finding_id=stable_uuid(f"{event_id(event)}:{resource_id}:role-assignment"),
        finding_code="OPENSTACK_PROJECT_ADMIN_ASSIGNMENT",
        scanner="openstack_notifications",
        provider="openstack",
        severity=SeverityLevel.CRITICAL,
        title="OpenStack user has admin role on project after runtime change",
        description=f"User {user_name} is assigned role `{role_name}` on project {project_name}.",
        resource_type="role_assignment",
        resource_id=resource_id,
        resource_name=user_name,
        cis_controls=["OpenStack-Identity-LeastPrivilege"],
        risk_category="identity_privilege",
        remediation_available=True,
        remediation_type="ansible",
        detected_at=detected_at,
        last_seen_at=detected_at,
        metadata={
            "role": role_name,
            "project": project_name,
            "event_id": event_id(event),
            "event_type": event_type(event),
            "event_time": detected_at.isoformat().replace("+00:00", "Z"),
            "file_path": "iac/openstack/m3_identity_overprivilege.tf",
            "environment": "runtime-event",
        },
        tags={"provider": "openstack", "flow": "event-driven"},
    )


def resolve_sg_rule_context(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = get_payload(event)
    rule_id = str(get_first(payload, "rule_id", "security_group_rule_id", "id", "ID") or "")
    if not rule_id:
        return {}
    rule = run_openstack_json(["openstack", "security", "group", "rule", "show", rule_id, "-f", "json"])
    security_group_id = str(get_first(rule, "security_group_id", "Security Group", "security_group") or "")
    sg_name = security_group_id
    if security_group_id:
        sg = run_openstack_json(["openstack", "security", "group", "show", security_group_id, "-f", "json"])
        sg_name = str(get_first(sg, "name", "Name", "id", "ID") or security_group_id)
    return {
        "rule_id": rule_id,
        "security_group_id": security_group_id,
        "security_group_name": sg_name,
        "direction": str(get_first(rule, "direction", "Direction") or "").lower(),
        "remote_ip": str(get_first(rule, "remote_ip_prefix", "IP Range", "ip_range") or ""),
        "protocol": str(get_first(rule, "protocol", "IP Protocol", "ip_protocol") or "any").lower(),
        "port_range": str(
            get_first(rule, "port_range", "Port Range", "port_range_min", "ports") or "all"
        ),
    }


def wide_open_rule(context: Dict[str, Any]) -> bool:
    if str(context.get("direction") or "").lower() != "ingress":
        return False
    remote_ip = str(context.get("remote_ip") or "")
    if remote_ip not in {"0.0.0.0/0", "::/0"}:
        return False
    protocol = str(context.get("protocol") or "any").lower()
    port_range = str(context.get("port_range") or "all")
    return protocol == "any" or "22" in port_range or "3389" in port_range


def make_sg_rule_finding(event: Dict[str, Any], context: Dict[str, Any]) -> NormalizedFinding:
    detected_at = event_time(event)
    return NormalizedFinding(
        finding_id=stable_uuid(f"{event_id(event)}:{context['rule_id']}:sg-rule"),
        finding_code="OPENSTACK_SG_WIDE_OPEN",
        scanner="openstack_notifications",
        provider="openstack",
        severity=SeverityLevel.HIGH,
        title="OpenStack security group allows inbound access from anywhere after runtime change",
        description=(
            f"Security group {context['security_group_name']} exposes protocol `{context['protocol']}` on "
            f"`{context['port_range']}` to `{context['remote_ip']}`."
        ),
        resource_type="security_group_rule",
        resource_id=str(context["rule_id"]),
        resource_name=str(context["security_group_name"]),
        cis_controls=["OpenStack-Network-LeastExposure"],
        risk_category="network_exposure",
        remediation_available=True,
        remediation_type="ansible",
        detected_at=detected_at,
        last_seen_at=detected_at,
        metadata={
            "rule_id": context["rule_id"],
            "security_group_id": context["security_group_id"],
            "security_group_name": context["security_group_name"],
            "direction": context["direction"],
            "remote_ip": context["remote_ip"],
            "protocol": context["protocol"],
            "port_range": context["port_range"],
            "event_id": event_id(event),
            "event_type": event_type(event),
            "event_time": detected_at.isoformat().replace("+00:00", "Z"),
            "file_path": "iac/openstack/m2_network_exposure.tf",
            "environment": "runtime-event",
        },
        tags={"provider": "openstack", "flow": "event-driven"},
    )


def evaluate_role_assignment_event(event: Dict[str, Any]) -> List[NormalizedFinding]:
    context = resolve_role_assignment_context(event)
    if "admin" not in str(context.get("role_name") or "").lower():
        return []
    if not context.get("project_id") and not context.get("project_name"):
        return []
    if not context.get("user_id") and not context.get("user_name"):
        return []
    if not role_assignment_still_exists(context):
        return []
    return [make_role_assignment_finding(event, context)]


def evaluate_security_group_rule_event(event: Dict[str, Any]) -> List[NormalizedFinding]:
    context = resolve_sg_rule_context(event)
    if not context or not wide_open_rule(context):
        return []
    return [make_sg_rule_finding(event, context)]


def evaluate_event(event: Dict[str, Any]) -> Tuple[str, List[NormalizedFinding]]:
    if is_role_assignment_event(event):
        return "role_assignment", evaluate_role_assignment_event(event)
    if is_security_group_rule_event(event):
        return "security_group_rule", evaluate_security_group_rule_event(event)
    return "unsupported", []


def deduplicate_findings(findings: Iterable[NormalizedFinding]) -> List[NormalizedFinding]:
    deduped: Dict[str, NormalizedFinding] = {}
    for finding in findings:
        deduped[finding.finding_id] = finding
    return list(deduped.values())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process OpenStack notifications into normalized findings")
    parser.add_argument("--event-file", action="append", default=[], help="Path to an OpenStack notification JSON file")
    parser.add_argument("--rabbitmq-url", help="Read JSON notifications directly from this AMQP URL")
    parser.add_argument("--rabbitmq-queue", default="notifications")
    parser.add_argument("--rabbitmq-exchange", default="openstack")
    parser.add_argument("--rabbitmq-routing-key", default="notifications.info")
    parser.add_argument("--max-messages", type=int, default=10)
    parser.add_argument("--ack-consumed", action="store_true")
    parser.add_argument("--declare-queue", action="store_true")
    parser.add_argument("--durable-queue", action="store_true")
    parser.add_argument("--pipeline-source", default="openstack-notifications-runtime")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--output-dir", default=str(ARTIFACTS_ROOT / "openstack"))
    parser.add_argument("--publish-to-siem", action="store_true")
    parser.add_argument("--execute-remediation", action="store_true")
    parser.add_argument("--approve-finding-id", action="append", default=[])
    parser.add_argument("--build-metrics", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    payloads = load_event_payloads(args.event_file)
    if args.rabbitmq_url:
        payloads.extend(
            consume_rabbitmq_messages(
                amqp_url=args.rabbitmq_url,
                queue=args.rabbitmq_queue,
                max_messages=args.max_messages,
                ack_consumed=args.ack_consumed,
                exchange=args.rabbitmq_exchange,
                routing_key=args.rabbitmq_routing_key,
                declare_queue=args.declare_queue,
                durable_queue=args.durable_queue,
            )
        )

    all_findings: List[NormalizedFinding] = []
    event_results: List[Dict[str, Any]] = []
    for payload in payloads:
        kind, findings = evaluate_event(payload)
        all_findings.extend(findings)
        event_results.append(
            {
                "event_id": event_id(payload),
                "event_type": event_type(payload),
                "kind": kind,
                "findings_emitted": len(findings),
            }
        )

    findings = deduplicate_findings(all_findings)
    decisions = triage_findings(findings)

    findings_path = output_dir / "findings.json"
    decisions_path = output_dir / "decisions.json"
    summary_path = output_dir / "summary.json"
    save_json(findings_path, finding_dicts(findings))
    save_json(decisions_path, decisions)
    save_json(
        summary_path,
        {
            "processed_events": len(payloads),
            "findings_emitted": len(findings),
            "decisions_emitted": len(decisions),
            "event_results": event_results,
        },
    )

    remediation_event_paths: List[Path] = []
    metric_paths: List[Path] = []
    if args.execute_remediation and findings:
        remediation_outputs = run_runtime_remediation(
            provider="openstack",
            findings_path=findings_path,
            decisions_path=decisions_path,
            output_dir=output_dir / "remediation",
            pipeline_source=f"{args.pipeline_source}-remediation",
            branch=args.branch,
            commit_sha=args.commit_sha,
            execute=True,
            approved_finding_ids=args.approve_finding_id,
        )
        remediation_event_paths.append(remediation_outputs["events_path"])
        if args.build_metrics:
            metric_paths.append(
                build_metrics(
                    findings_path=findings_path,
                    decisions_path=decisions_path,
                    remediation_event_paths=remediation_event_paths,
                    output_path=output_dir / "remediation_metrics.json",
                    pipeline_source=f"{args.pipeline_source}-metrics",
                    branch=args.branch,
                    commit_sha=args.commit_sha,
                )
            )

    if args.publish_to_siem and findings:
        publish_to_siem(
            findings_path=findings_path,
            decisions_path=decisions_path,
            remediation_event_paths=remediation_event_paths,
            metrics_paths=metric_paths,
            pipeline_source=args.pipeline_source,
            branch=args.branch,
            commit_sha=args.commit_sha,
        )

    logger.info("Processed %s OpenStack notifications and emitted %s findings", len(payloads), len(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
