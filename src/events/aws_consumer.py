"""
Consume AWS change events, enrich current runtime state, and emit normalized findings.
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
    return str(uuid5(NAMESPACE_URL, f"aws-event-consumer:{seed}"))


def run_aws_json(args: List[str], *, region: str = "") -> Any:
    command = ["aws", *args]
    if region and "--region" not in command:
        command.extend(["--region", region])
    if "--output" not in command:
        command.extend(["--output", "json"])
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


def receive_sqs_messages(queue_url: str, *, max_messages: int, wait_time_seconds: int, region: str) -> List[Dict[str, Any]]:
    payload = run_aws_json(
        [
            "sqs",
            "receive-message",
            "--queue-url",
            queue_url,
            "--max-number-of-messages",
            str(max_messages),
            "--wait-time-seconds",
            str(wait_time_seconds),
            "--attribute-names",
            "All",
            "--message-attribute-names",
            "All",
        ],
        region=region,
    )
    messages = payload.get("Messages", []) if isinstance(payload, dict) else []
    return [item for item in messages if isinstance(item, dict)]


def delete_sqs_message(queue_url: str, receipt_handle: str, *, region: str) -> None:
    run_aws_json(
        [
            "sqs",
            "delete-message",
            "--queue-url",
            queue_url,
            "--receipt-handle",
            receipt_handle,
        ],
        region=region,
    )


def unwrap_eventbridge_message(message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    body = message.get("Body")
    if not isinstance(body, str):
        return None
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def get_detail(event: Dict[str, Any]) -> Dict[str, Any]:
    detail = event.get("detail")
    return detail if isinstance(detail, dict) else {}


def event_name(event: Dict[str, Any]) -> str:
    detail = get_detail(event)
    return str(detail.get("eventName") or detail.get("messageType") or event.get("event_type") or "")


def event_region(event: Dict[str, Any], default_region: str) -> str:
    detail = get_detail(event)
    return str(event.get("region") or detail.get("awsRegion") or detail.get("region") or default_region)


def event_id(event: Dict[str, Any]) -> str:
    detail = get_detail(event)
    return str(detail.get("eventID") or event.get("id") or event.get("event_id") or stable_uuid(json.dumps(event, sort_keys=True)))


def event_time(event: Dict[str, Any]) -> datetime:
    detail = get_detail(event)
    return utc_from_event(event.get("time") or detail.get("eventTime") or event.get("event_time"))


def actor_identity(event: Dict[str, Any]) -> str:
    detail = get_detail(event)
    user_identity = detail.get("userIdentity")
    if isinstance(user_identity, dict):
        return str(
            user_identity.get("arn")
            or user_identity.get("principalId")
            or user_identity.get("userName")
            or "unknown"
        )
    return "unknown"


def source_ip(event: Dict[str, Any]) -> str:
    detail = get_detail(event)
    return str(detail.get("sourceIPAddress") or "")


def supported_api_event(event: Dict[str, Any]) -> bool:
    detail = get_detail(event)
    if str(event.get("detail-type") or "") != "AWS API Call via CloudTrail":
        return False
    source = str(detail.get("eventSource") or "")
    name = str(detail.get("eventName") or "")
    supported = {
        ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress"),
        ("ec2.amazonaws.com", "RevokeSecurityGroupIngress"),
        ("ec2.amazonaws.com", "ModifySecurityGroupRules"),
        ("ec2.amazonaws.com", "CreateSecurityGroup"),
        ("s3.amazonaws.com", "PutBucketPolicy"),
        ("s3.amazonaws.com", "DeleteBucketPolicy"),
        ("s3.amazonaws.com", "PutPublicAccessBlock"),
        ("s3.amazonaws.com", "DeletePublicAccessBlock"),
        ("s3.amazonaws.com", "PutBucketAcl"),
        ("iam.amazonaws.com", "AttachRolePolicy"),
        ("iam.amazonaws.com", "AttachUserPolicy"),
        ("iam.amazonaws.com", "PutRolePolicy"),
        ("iam.amazonaws.com", "PutUserPolicy"),
        ("iam.amazonaws.com", "PutGroupPolicy"),
    }
    return (source, name) in supported


def supported_config_event(event: Dict[str, Any]) -> bool:
    detail_type = str(event.get("detail-type") or "")
    return detail_type in {"Config Configuration Item Change", "Config Rules Compliance Change"}


def event_targets_security_group(event: Dict[str, Any]) -> bool:
    detail = get_detail(event)
    if supported_api_event(event):
        return str(detail.get("eventSource") or "") == "ec2.amazonaws.com"
    if supported_config_event(event):
        resource_type = str(detail.get("resourceType") or ((detail.get("configurationItem") or {}).get("resourceType")) or "")
        return resource_type == "AWS::EC2::SecurityGroup"
    return False


def event_targets_bucket(event: Dict[str, Any]) -> bool:
    detail = get_detail(event)
    if supported_api_event(event):
        return str(detail.get("eventSource") or "") == "s3.amazonaws.com"
    if supported_config_event(event):
        resource_type = str(detail.get("resourceType") or ((detail.get("configurationItem") or {}).get("resourceType")) or "")
        return resource_type == "AWS::S3::Bucket"
    return False


def event_targets_iam(event: Dict[str, Any]) -> bool:
    detail = get_detail(event)
    if supported_api_event(event):
        return str(detail.get("eventSource") or "") == "iam.amazonaws.com"
    if supported_config_event(event):
        resource_type = str(detail.get("resourceType") or ((detail.get("configurationItem") or {}).get("resourceType")) or "")
        return resource_type in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Policy"}
    return False


def extract_security_group_id(event: Dict[str, Any]) -> str:
    detail = get_detail(event)
    request = detail.get("requestParameters") if isinstance(detail.get("requestParameters"), dict) else {}
    response = detail.get("responseElements") if isinstance(detail.get("responseElements"), dict) else {}
    if request.get("groupId"):
        return str(request["groupId"])
    if response.get("groupId"):
        return str(response["groupId"])
    if supported_config_event(event):
        config_item = detail.get("configurationItem") if isinstance(detail.get("configurationItem"), dict) else {}
        return str(detail.get("resourceId") or config_item.get("resourceId") or "")
    return ""


def extract_bucket_name(event: Dict[str, Any]) -> str:
    detail = get_detail(event)
    request = detail.get("requestParameters") if isinstance(detail.get("requestParameters"), dict) else {}
    bucket_name = request.get("bucketName")
    if bucket_name:
        return str(bucket_name)
    if supported_config_event(event):
        config_item = detail.get("configurationItem") if isinstance(detail.get("configurationItem"), dict) else {}
        return str(detail.get("resourceId") or config_item.get("resourceName") or config_item.get("resourceId") or "")
    return ""


def extract_iam_target(event: Dict[str, Any]) -> Tuple[str, str]:
    detail = get_detail(event)
    request = detail.get("requestParameters") if isinstance(detail.get("requestParameters"), dict) else {}
    for key, resource_type in (
        ("roleName", "aws_iam_role"),
        ("userName", "aws_iam_user"),
        ("groupName", "aws_iam_group"),
    ):
        value = request.get(key)
        if value:
            return resource_type, str(value)
    if supported_config_event(event):
        config_item = detail.get("configurationItem") if isinstance(detail.get("configurationItem"), dict) else {}
        resource_type = str(detail.get("resourceType") or config_item.get("resourceType") or "")
        resource_name = str(config_item.get("resourceName") or detail.get("resourceId") or config_item.get("resourceId") or "")
        type_map = {
            "AWS::IAM::Role": "aws_iam_role",
            "AWS::IAM::User": "aws_iam_user",
            "AWS::IAM::Group": "aws_iam_group",
            "AWS::IAM::Policy": "aws_iam_policy",
        }
        return type_map.get(resource_type, "aws_iam_principal"), resource_name
    return "aws_iam_principal", ""


def normalize_permission_range(permission: Dict[str, Any]) -> str:
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None and to_port is None:
        return "all"
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}:{to_port}"


def risky_sg_permissions(security_group: Dict[str, Any]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for permission in security_group.get("IpPermissions", []) or []:
        protocol = str(permission.get("IpProtocol") or "all").lower()
        port_range = normalize_permission_range(permission)
        networks = [item.get("CidrIp") for item in permission.get("IpRanges", []) if item.get("CidrIp")]
        networks.extend(item.get("CidrIpv6") for item in permission.get("Ipv6Ranges", []) if item.get("CidrIpv6"))
        networks = [network for network in networks if network]
        if not any(network in {"0.0.0.0/0", "::/0"} for network in networks):
            continue
        risky = protocol in {"-1", "all"} or "22" in port_range or "3389" in port_range
        if not risky:
            continue
        matches.append(
            {
                "protocol": protocol,
                "port_range": port_range,
                "networks": networks,
            }
        )
    return matches


def s3_public_violation(bucket_state: Dict[str, Any]) -> bool:
    public_access_block = bucket_state.get("public_access_block") or {}
    policy_status = bucket_state.get("policy_status") or {}
    acl_grants = bucket_state.get("acl_grants") or []
    block_flags = {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    }
    disabled_block = any(public_access_block.get(flag) is False for flag in block_flags)
    public_policy = bool(policy_status.get("IsPublic"))
    public_acl = any(grant.get("grantee") in {"AllUsers", "AuthenticatedUsers"} for grant in acl_grants)
    return disabled_block or public_policy or public_acl


def policy_document_has_wildcards(policy_document: Dict[str, Any]) -> bool:
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if any(str(action).strip() == "*" for action in actions) and any(str(resource).strip() == "*" for resource in resources):
            return True
    return False


def describe_security_group(group_id: str, *, region: str) -> Dict[str, Any]:
    payload = run_aws_json(
        ["ec2", "describe-security-groups", "--group-ids", group_id, "--query", "SecurityGroups[0]"],
        region=region,
    )
    if not isinstance(payload, dict):
        raise RuntimeError(f"Security group {group_id} not found")
    return payload


def get_bucket_state(bucket_name: str, *, region: str) -> Dict[str, Any]:
    public_access_block: Dict[str, Any] = {}
    policy_status: Dict[str, Any] = {}
    acl_grants: List[Dict[str, Any]] = []

    get_block = subprocess.run(
        ["aws", "s3api", "get-public-access-block", "--bucket", bucket_name, "--region", region, "--output", "json"],
        check=False,
        text=True,
        capture_output=True,
    )
    if get_block.returncode == 0:
        payload = json.loads(get_block.stdout or "{}")
        public_access_block = payload.get("PublicAccessBlockConfiguration", {})

    get_policy_status = subprocess.run(
        ["aws", "s3api", "get-bucket-policy-status", "--bucket", bucket_name, "--region", region, "--output", "json"],
        check=False,
        text=True,
        capture_output=True,
    )
    if get_policy_status.returncode == 0:
        payload = json.loads(get_policy_status.stdout or "{}")
        policy_status = payload.get("PolicyStatus", {})

    get_acl = subprocess.run(
        ["aws", "s3api", "get-bucket-acl", "--bucket", bucket_name, "--region", region, "--output", "json"],
        check=False,
        text=True,
        capture_output=True,
    )
    if get_acl.returncode == 0:
        payload = json.loads(get_acl.stdout or "{}")
        for grant in payload.get("Grants", []):
            if not isinstance(grant, dict):
                continue
            grantee = grant.get("Grantee") if isinstance(grant.get("Grantee"), dict) else {}
            uri = str(grantee.get("URI") or "")
            group_name = ""
            if uri.endswith("/AllUsers"):
                group_name = "AllUsers"
            elif uri.endswith("/AuthenticatedUsers"):
                group_name = "AuthenticatedUsers"
            acl_grants.append({"permission": grant.get("Permission"), "grantee": group_name})

    return {
        "bucket_name": bucket_name,
        "public_access_block": public_access_block,
        "policy_status": policy_status,
        "acl_grants": acl_grants,
    }


def get_iam_policy_document(policy_arn: str) -> Optional[Dict[str, Any]]:
    try:
        policy = run_aws_json(["iam", "get-policy", "--policy-arn", policy_arn])
    except RuntimeError:
        return None
    default_version = ((policy or {}).get("Policy") or {}).get("DefaultVersionId")
    if not default_version:
        return None
    try:
        version = run_aws_json(
            [
                "iam",
                "get-policy-version",
                "--policy-arn",
                policy_arn,
                "--version-id",
                str(default_version),
            ]
        )
    except RuntimeError:
        return None
    document = (((version or {}).get("PolicyVersion") or {}).get("Document"))
    return document if isinstance(document, dict) else None


def inline_policy_document(command: List[str]) -> Optional[Dict[str, Any]]:
    try:
        payload = run_aws_json(command)
    except RuntimeError:
        return None
    for key in ("RolePolicy", "UserPolicy", "GroupPolicy"):
        document = (payload.get(key) or {}).get("PolicyDocument")
        if isinstance(document, dict):
            return document
    return None


def get_iam_principal_policies(resource_type: str, resource_name: str) -> List[str]:
    if resource_type == "aws_iam_role":
        payload = run_aws_json(["iam", "list-attached-role-policies", "--role-name", resource_name])
        return [item.get("PolicyArn") for item in payload.get("AttachedPolicies", []) if item.get("PolicyArn")]
    if resource_type == "aws_iam_user":
        payload = run_aws_json(["iam", "list-attached-user-policies", "--user-name", resource_name])
        return [item.get("PolicyArn") for item in payload.get("AttachedPolicies", []) if item.get("PolicyArn")]
    if resource_type == "aws_iam_group":
        payload = run_aws_json(["iam", "list-attached-group-policies", "--group-name", resource_name])
        return [item.get("PolicyArn") for item in payload.get("AttachedPolicies", []) if item.get("PolicyArn")]
    return []


def make_sg_finding(event: Dict[str, Any], security_group: Dict[str, Any], violations: List[Dict[str, Any]]) -> NormalizedFinding:
    detected_at = event_time(event)
    group_id = str(security_group.get("GroupId") or "")
    group_name = str(security_group.get("GroupName") or group_id)
    region = event_region(event, "")
    return NormalizedFinding(
        finding_id=stable_uuid(f"{event_id(event)}:{group_id}:sg"),
        finding_code="AWS_EVENT_OPEN_SECURITY_GROUP",
        scanner="aws_eventbridge",
        provider="aws",
        severity=SeverityLevel.HIGH,
        title="AWS security group was opened to the internet after deployment",
        description=(
            f"Security group {group_name} currently exposes risky ingress rules to the internet after "
            f"event `{event_name(event)}`."
        ),
        resource_type="aws_security_group",
        resource_id=group_id,
        resource_name=group_name,
        region=region,
        cis_controls=["AWS-CIS-4.1"],
        risk_category="network_exposure",
        remediation_available=True,
        remediation_type="ansible",
        detected_at=detected_at,
        last_seen_at=detected_at,
        metadata={
            "file_path": "iac/aws/m2_wide_open_sg.tf",
            "event_id": event_id(event),
            "event_name": event_name(event),
            "event_time": detected_at.isoformat().replace("+00:00", "Z"),
            "actor": actor_identity(event),
            "source_ip": source_ip(event),
            "ingress_rules": violations,
            "environment": "runtime-event",
        },
        tags={"provider": "aws", "flow": "event-driven"},
    )


def make_s3_finding(event: Dict[str, Any], bucket_state: Dict[str, Any]) -> NormalizedFinding:
    detected_at = event_time(event)
    bucket_name = str(bucket_state.get("bucket_name") or "")
    return NormalizedFinding(
        finding_id=stable_uuid(f"{event_id(event)}:{bucket_name}:s3"),
        finding_code="AWS_EVENT_PUBLIC_S3",
        scanner="aws_eventbridge",
        provider="aws",
        severity=SeverityLevel.HIGH,
        title="AWS S3 bucket became publicly exposed after deployment",
        description=(
            f"S3 bucket {bucket_name} currently has public exposure indicators after event `{event_name(event)}`."
        ),
        resource_type="aws_s3_bucket",
        resource_id=bucket_name,
        resource_name=bucket_name,
        region=event_region(event, ""),
        cis_controls=["AWS-CIS-2.1.1"],
        risk_category="data_exposure",
        remediation_available=True,
        remediation_type="cloud_custodian",
        detected_at=detected_at,
        last_seen_at=detected_at,
        metadata={
            "file_path": "iac/aws/m1_public_s3.tf",
            "event_id": event_id(event),
            "event_name": event_name(event),
            "event_time": detected_at.isoformat().replace("+00:00", "Z"),
            "actor": actor_identity(event),
            "source_ip": source_ip(event),
            "public_access_block": bucket_state.get("public_access_block"),
            "policy_status": bucket_state.get("policy_status"),
            "acl_grants": bucket_state.get("acl_grants"),
            "environment": "runtime-event",
        },
        tags={"provider": "aws", "flow": "event-driven"},
    )


def make_iam_finding(
    event: Dict[str, Any],
    *,
    resource_type: str,
    resource_name: str,
    policy_refs: List[str],
) -> NormalizedFinding:
    detected_at = event_time(event)
    return NormalizedFinding(
        finding_id=stable_uuid(f"{event_id(event)}:{resource_type}:{resource_name}:iam"),
        finding_code="AWS_EVENT_IAM_WILDCARD",
        scanner="aws_eventbridge",
        provider="aws",
        severity=SeverityLevel.CRITICAL,
        title="AWS IAM wildcard privilege detected after runtime change",
        description=(
            f"IAM principal {resource_name} now references wildcard permissions after event `{event_name(event)}`."
        ),
        resource_type=resource_type,
        resource_id=resource_name,
        resource_name=resource_name,
        region=event_region(event, ""),
        cis_controls=["AWS-CIS-1.22"],
        risk_category="identity_privilege",
        remediation_available=False,
        remediation_type="manual",
        detected_at=detected_at,
        last_seen_at=detected_at,
        metadata={
            "file_path": "iac/aws/m3_iam_wildcard.tf",
            "event_id": event_id(event),
            "event_name": event_name(event),
            "event_time": detected_at.isoformat().replace("+00:00", "Z"),
            "actor": actor_identity(event),
            "source_ip": source_ip(event),
            "policy_references": policy_refs,
            "environment": "runtime-event",
        },
        tags={"provider": "aws", "flow": "event-driven"},
    )


def evaluate_security_group_event(event: Dict[str, Any], *, region: str) -> List[NormalizedFinding]:
    group_id = extract_security_group_id(event)
    if not group_id:
        return []
    security_group = describe_security_group(group_id, region=region)
    violations = risky_sg_permissions(security_group)
    if not violations:
        return []
    return [make_sg_finding(event, security_group, violations)]


def evaluate_bucket_event(event: Dict[str, Any], *, region: str) -> List[NormalizedFinding]:
    bucket_name = extract_bucket_name(event)
    if not bucket_name:
        return []
    state = get_bucket_state(bucket_name, region=region)
    if not s3_public_violation(state):
        return []
    return [make_s3_finding(event, state)]


def evaluate_iam_event(event: Dict[str, Any]) -> List[NormalizedFinding]:
    resource_type, resource_name = extract_iam_target(event)
    if not resource_name:
        return []

    detail = get_detail(event)
    request = detail.get("requestParameters") if isinstance(detail.get("requestParameters"), dict) else {}
    policy_refs: List[str] = []

    policy_arn = str(request.get("policyArn") or "")
    if policy_arn:
        document = get_iam_policy_document(policy_arn)
        if document and policy_document_has_wildcards(document):
            policy_refs.append(policy_arn)

    if not policy_refs and event_name(event) in {"PutRolePolicy", "PutUserPolicy", "PutGroupPolicy"}:
        if resource_type == "aws_iam_role":
            document = inline_policy_document(["iam", "get-role-policy", "--role-name", resource_name, "--policy-name", str(request.get("policyName") or "")])
        elif resource_type == "aws_iam_user":
            document = inline_policy_document(["iam", "get-user-policy", "--user-name", resource_name, "--policy-name", str(request.get("policyName") or "")])
        else:
            document = inline_policy_document(["iam", "get-group-policy", "--group-name", resource_name, "--policy-name", str(request.get("policyName") or "")])
        if document and policy_document_has_wildcards(document):
            policy_refs.append(str(request.get("policyName") or "inline-policy"))

    if not policy_refs:
        for attached_policy_arn in get_iam_principal_policies(resource_type, resource_name):
            document = get_iam_policy_document(attached_policy_arn)
            if document and policy_document_has_wildcards(document):
                policy_refs.append(attached_policy_arn)

    if not policy_refs:
        return []
    return [make_iam_finding(event, resource_type=resource_type, resource_name=resource_name, policy_refs=policy_refs)]


def evaluate_event(event: Dict[str, Any], *, default_region: str) -> Tuple[str, List[NormalizedFinding]]:
    region = event_region(event, default_region)
    if event_targets_security_group(event):
        return "security_group", evaluate_security_group_event(event, region=region)
    if event_targets_bucket(event):
        return "s3_bucket", evaluate_bucket_event(event, region=region)
    if event_targets_iam(event):
        return "iam", evaluate_iam_event(event)
    return "unsupported", []


def deduplicate_findings(findings: Iterable[NormalizedFinding]) -> List[NormalizedFinding]:
    deduped: Dict[str, NormalizedFinding] = {}
    for finding in findings:
        deduped[finding.finding_id] = finding
    return list(deduped.values())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process AWS change events into normalized findings")
    parser.add_argument("--event-file", action="append", default=[], help="Path to an EventBridge/CloudTrail/Config event JSON file")
    parser.add_argument("--sqs-queue-url", help="Read EventBridge events from this SQS queue instead of only local files")
    parser.add_argument("--max-messages", type=int, default=10, help="Maximum number of SQS messages to consume in one run")
    parser.add_argument("--wait-time-seconds", type=int, default=5, help="SQS long-poll wait time")
    parser.add_argument("--delete-consumed", action="store_true", help="Delete consumed SQS messages after processing")
    parser.add_argument("--region", default="ap-southeast-1")
    parser.add_argument("--project-prefix", default="threat-demo")
    parser.add_argument("--pipeline-source", default="aws-eventbridge-runtime")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--output-dir", default=str(ARTIFACTS_ROOT / "aws"))
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
    consumed_messages: List[Dict[str, Any]] = []
    if args.sqs_queue_url:
        consumed_messages = receive_sqs_messages(
            args.sqs_queue_url,
            max_messages=args.max_messages,
            wait_time_seconds=args.wait_time_seconds,
            region=args.region,
        )
        payloads.extend(
            payload
            for payload in (unwrap_eventbridge_message(message) for message in consumed_messages)
            if payload
        )

    all_findings: List[NormalizedFinding] = []
    event_results: List[Dict[str, Any]] = []
    for payload in payloads:
        kind, findings = evaluate_event(payload, default_region=args.region)
        all_findings.extend(findings)
        event_results.append(
            {
                "event_id": event_id(payload),
                "event_name": event_name(payload),
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
            "consumed_sqs_messages": len(consumed_messages),
            "findings_emitted": len(findings),
            "decisions_emitted": len(decisions),
            "event_results": event_results,
        },
    )

    remediation_event_paths: List[Path] = []
    metric_paths: List[Path] = []
    if args.execute_remediation and findings:
        remediation_outputs = run_runtime_remediation(
            provider="aws",
            findings_path=findings_path,
            decisions_path=decisions_path,
            output_dir=output_dir / "remediation",
            pipeline_source=f"{args.pipeline_source}-remediation",
            branch=args.branch,
            commit_sha=args.commit_sha,
            execute=True,
            approved_finding_ids=args.approve_finding_id,
            region=args.region,
            project_prefix=args.project_prefix,
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

    if args.delete_consumed and args.sqs_queue_url:
        for message in consumed_messages:
            receipt_handle = str(message.get("ReceiptHandle") or "")
            if receipt_handle:
                delete_sqs_message(args.sqs_queue_url, receipt_handle, region=args.region)

    logger.info("Processed %s AWS events and emitted %s findings", len(payloads), len(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
