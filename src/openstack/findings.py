"""
Build normalized findings from OpenStack evidence exports.
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import uuid5, NAMESPACE_URL

from ..models import NormalizedFinding, SeverityLevel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def get_first(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def finding_uuid(code: str, resource_id: str, discriminator: str = "") -> str:
    seed = f"openstack:{code}:{resource_id}:{discriminator}"
    return str(uuid5(NAMESPACE_URL, seed))


def make_finding(
    *,
    code: str,
    severity: SeverityLevel,
    title: str,
    description: str,
    resource_type: str,
    resource_id: str,
    resource_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> NormalizedFinding:
    now = datetime.utcnow()
    discriminator = json.dumps(metadata or {}, sort_keys=True, default=str)
    return NormalizedFinding(
        finding_id=finding_uuid(code, resource_id, discriminator),
        finding_code=code,
        scanner="openstack_custom",
        provider="openstack",
        severity=severity,
        title=title,
        description=description,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        region=None,
        risk_category="misconfiguration",
        remediation_available=True,
        remediation_type="ansible",
        detected_at=now,
        last_seen_at=now,
        metadata=metadata or {},
        tags={"provider": "openstack"},
    )


def parse_public_container(path: str) -> List[NormalizedFinding]:
    payload = load_json_file(path)
    if not isinstance(payload, dict):
        return []

    read_acl = str(
        get_first(payload, "read_ACL", "read_acl", "Read ACL", "x-container-read") or ""
    )
    is_public = ".r:*" in read_acl or ".rlistings" in read_acl
    if not is_public:
        return []

    resource_name = str(get_first(payload, "name", "Name", "container", "Container") or "unknown")
    resource_id = str(get_first(payload, "id", "ID", "container", "Container") or resource_name)

    return [
        make_finding(
            code="OPENSTACK_SWIFT_PUBLIC_READ",
            severity=SeverityLevel.HIGH,
            title="OpenStack Swift container allows public read",
            description=(
                f"Container {resource_name} exposes public read/listing ACLs via `{read_acl}`."
            ),
            resource_type="swift_container",
            resource_id=resource_id,
            resource_name=resource_name,
            metadata={"read_acl": read_acl},
        )
    ]


def parse_security_group_rules(path: str) -> List[NormalizedFinding]:
    payload = load_json_file(path)
    if not isinstance(payload, list):
        return []

    findings: List[NormalizedFinding] = []
    for rule in payload:
        if not isinstance(rule, dict):
            continue

        direction = str(get_first(rule, "Direction", "direction") or "").lower()
        remote_ip = str(get_first(rule, "IP Range", "ip_range", "remote_ip_prefix") or "")
        protocol = str(get_first(rule, "IP Protocol", "ip_protocol", "protocol") or "any").lower()
        port_range = str(get_first(rule, "Port Range", "port_range", "ports") or "all")
        resource_name = str(get_first(rule, "Security Group", "security_group", "Name") or "unknown-sg")
        resource_id = str(get_first(rule, "Security Group ID", "security_group_id", "ID") or resource_name)

        if direction != "ingress":
            continue
        if remote_ip not in {"0.0.0.0/0", "::/0"}:
            continue

        risky = protocol == "any" or "22" in port_range or "3389" in port_range
        if not risky:
            continue

        findings.append(
            make_finding(
                code="OPENSTACK_SG_WIDE_OPEN",
                severity=SeverityLevel.HIGH,
                title="OpenStack security group allows inbound access from anywhere",
                description=(
                    f"Security group {resource_name} exposes protocol `{protocol}` on "
                    f"`{port_range}` to `{remote_ip}`."
                ),
                resource_type="security_group",
                resource_id=resource_id,
                resource_name=resource_name,
                metadata={
                    "direction": direction,
                    "remote_ip": remote_ip,
                    "protocol": protocol,
                    "port_range": port_range,
                },
            )
        )

    return findings


def parse_role_assignments(path: str) -> List[NormalizedFinding]:
    payload = load_json_file(path)
    if not isinstance(payload, list):
        return []

    findings: List[NormalizedFinding] = []
    for assignment in payload:
        if not isinstance(assignment, dict):
            continue

        role = str(get_first(assignment, "Role", "role") or "")
        if "admin" not in role.lower():
            continue

        user_name = str(get_first(assignment, "User", "user") or "unknown-user")
        project_name = str(get_first(assignment, "Project", "project") or "unknown-project")
        resource_id = f"{project_name}:{user_name}:{role}"

        findings.append(
            make_finding(
                code="OPENSTACK_PROJECT_ADMIN_ASSIGNMENT",
                severity=SeverityLevel.CRITICAL,
                title="OpenStack user has admin role on project",
                description=(
                    f"User {user_name} is assigned role `{role}` on project {project_name}."
                ),
                resource_type="role_assignment",
                resource_id=resource_id,
                resource_name=user_name,
                metadata={"role": role, "project": project_name},
            )
        )

    return findings


def save_findings(findings: Iterable[NormalizedFinding], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = [finding.model_dump(mode="json") for finding in findings]
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create normalized findings from OpenStack evidence")
    parser.add_argument("--container-file", help="Path to `openstack container show -f json` output")
    parser.add_argument("--sg-rules-file", help="Path to `openstack security group rule list -f json` output")
    parser.add_argument("--role-assignments-file", help="Path to `openstack role assignment list --names -f json` output")
    parser.add_argument("--output", default="./scan_results/openstack_findings.json", help="Output findings path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings: List[NormalizedFinding] = []

    if args.container_file:
        findings.extend(parse_public_container(args.container_file))
    if args.sg_rules_file:
        findings.extend(parse_security_group_rules(args.sg_rules_file))
    if args.role_assignments_file:
        findings.extend(parse_role_assignments(args.role_assignments_file))

    logger.info("Generated %s OpenStack findings", len(findings))
    save_findings(findings, args.output)
    logger.info("Wrote OpenStack findings to %s", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
