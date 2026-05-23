"""
Execute runtime remediation actions for provider findings.
"""
from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from uuid import NAMESPACE_URL, uuid5

from ..models import RemediationEvent, RemediationStatus, StatusEnum
from ..siem.publisher import load_decisions, load_findings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def normalize_iso(raw: Any) -> Optional[datetime]:
    if raw in (None, ""):
        return None
    text = str(raw).replace("Z", "+00:00")
    try:
        value = datetime.fromisoformat(text)
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0)


def event_uuid(kind: str, finding_id: str, command_seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"remediation:{kind}:{finding_id}:{command_seed}"))


def get_first(mapping: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def run_command(command: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=True,
    )


def openstack_available() -> bool:
    return shutil.which("openstack") is not None


def parse_rule_port_range(raw: str) -> Tuple[str, str]:
    if ":" in raw:
        start, end = raw.split(":", 1)
        return start.strip(), end.strip()
    if raw.lower() == "all":
        return "0", "0"
    return raw.strip(), raw.strip()


def filter_wide_open_rules(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        direction = str(get_first(row, "Direction", "direction") or "").lower()
        remote_ip = str(get_first(row, "IP Range", "ip_range", "remote_ip_prefix") or "")
        protocol = str(get_first(row, "IP Protocol", "ip_protocol", "protocol") or "any").lower()
        port_range = str(get_first(row, "Port Range", "port_range", "ports") or "all")
        if direction != "ingress":
            continue
        if remote_ip not in {"0.0.0.0/0", "::/0"}:
            continue
        if protocol == "any" or "22" in port_range or "3389" in port_range:
            matches.append(row)
    return matches


def remediation_plan_for_openstack(finding: Dict[str, Any]) -> Tuple[List[List[str]], Dict[str, Any]]:
    code = str(finding.get("finding_code") or "")
    resource_name = str(finding.get("resource_name") or finding.get("resource_id") or "")
    metadata = finding.get("metadata") or {}

    if code == "OPENSTACK_SWIFT_PUBLIC_READ":
        command = ["openstack", "container", "set", "--read-acl", "", resource_name]
        return [command], {"target": resource_name}

    if code == "OPENSTACK_PROJECT_ADMIN_ASSIGNMENT":
        project = str(metadata.get("project") or "")
        role = str(metadata.get("role") or "admin")
        user = str(finding.get("resource_name") or "")
        command = ["openstack", "role", "remove", "--project", project, "--user", user, role]
        return [command], {"project": project, "role": role, "user": user}

    if code == "OPENSTACK_SG_WIDE_OPEN":
        resource_id = str(finding.get("resource_id") or "")
        resource_name = str(finding.get("resource_name") or resource_id)
        list_command = ["openstack", "security", "group", "rule", "list", resource_name, "-f", "json"]
        return [list_command], {
            "resource_id": resource_id,
            "resource_name": resource_name,
            "port_range": metadata.get("port_range"),
            "remote_ip": metadata.get("remote_ip"),
        }

    raise ValueError(f"Unsupported OpenStack finding code: {code}")


def expand_openstack_sg_plan(initial_output: str) -> List[List[str]]:
    try:
        rows = json.loads(initial_output or "[]")
    except json.JSONDecodeError as exc:
        raise ValueError(f"Unable to parse security group rules JSON: {exc}") from exc

    deletions: List[List[str]] = []
    for row in filter_wide_open_rules(rows):
        rule_id = str(get_first(row, "ID", "id") or "")
        if rule_id:
            deletions.append(["openstack", "security", "group", "rule", "delete", rule_id])
    return deletions


def approval_granted(
    finding: Dict[str, Any],
    decision: Dict[str, Any],
    approved_ids: set[str],
    approve_all_manual: bool,
) -> bool:
    if decision.get("recommendation") == "auto_remediate":
        return True
    finding_id = str(finding.get("finding_id") or "")
    return approve_all_manual or finding_id in approved_ids


def update_finding_after_success(finding: Dict[str, Any], completed_at: datetime) -> Dict[str, Any]:
    updated = deepcopy(finding)
    updated["status"] = StatusEnum.REMEDIATED.value
    updated["remediation_status"] = RemediationStatus.SUCCESS.value
    updated["remediated_at"] = completed_at.isoformat().replace("+00:00", "Z")
    updated["last_seen_at"] = updated["remediated_at"]
    return updated


def create_event(
    *,
    finding: Dict[str, Any],
    decision: Dict[str, Any],
    status: RemediationStatus,
    started_at: datetime,
    completed_at: Optional[datetime],
    manual_approval: bool,
    dry_run: bool,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
    commands: List[List[str]],
    notes: str,
    metadata: Optional[Dict[str, Any]] = None,
    patch_path: Optional[str] = None,
    pr_artifact_dir: Optional[str] = None,
) -> RemediationEvent:
    duration_seconds = None
    if completed_at is not None:
        duration_seconds = round((completed_at - started_at).total_seconds(), 3)

    command_seed = "|".join(" ".join(command) for command in commands) or "noop"
    metadata_seed = json.dumps(metadata or {}, sort_keys=True, default=str)
    return RemediationEvent(
        event_id=event_uuid(
            "runtime",
            str(finding.get("finding_id") or ""),
            f"{command_seed}:{metadata_seed}",
        ),
        finding_id=str(finding.get("finding_id") or ""),
        finding_code=str(finding.get("finding_code") or ""),
        provider=str(finding.get("provider") or ""),
        resource_id=str(finding.get("resource_id") or ""),
        action_kind="runtime_remediation",
        recommendation=str(decision.get("recommendation") or "manual_review"),
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration_seconds,
        manual_approval=manual_approval,
        dry_run=dry_run,
        pipeline_source=pipeline_source,
        branch=branch,
        commit_sha=commit_sha,
        command=[" && ".join(" ".join(command) for command in commands)] if commands else None,
        patch_path=patch_path,
        pr_artifact_dir=pr_artifact_dir,
        notes=notes,
        metadata=metadata or {},
    )


def execute_openstack_plan(
    finding: Dict[str, Any],
    *,
    execute: bool,
    simulate_success: bool,
) -> Tuple[RemediationStatus, str, List[List[str]], Dict[str, Any]]:
    commands, metadata = remediation_plan_for_openstack(finding)

    if simulate_success:
        if str(finding.get("finding_code")) == "OPENSTACK_SG_WIDE_OPEN":
            commands = [["openstack", "security", "group", "rule", "delete", "<wide-open-rule-id>"]]
        return (
            RemediationStatus.SUCCESS,
            "Simulated successful remediation for demo flow.",
            commands,
            metadata,
        )

    if not execute:
        return (
            RemediationStatus.PENDING,
            "Dry-run only. No provider changes executed.",
            commands,
            metadata,
        )

    if not openstack_available():
        return (
            RemediationStatus.FAILED,
            "openstack CLI is not available on this machine.",
            commands,
            metadata,
        )

    code = str(finding.get("finding_code") or "")
    if code == "OPENSTACK_SG_WIDE_OPEN":
        first = run_command(commands[0])
        metadata["list_stdout"] = first.stdout
        metadata["list_stderr"] = first.stderr
        if first.returncode != 0:
            return RemediationStatus.FAILED, first.stderr.strip() or "Failed to list SG rules", commands, metadata
        delete_commands = expand_openstack_sg_plan(first.stdout)
        if not delete_commands:
            return RemediationStatus.SUCCESS, "No wide-open rules remain.", [], metadata
        commands = delete_commands

    executed: List[str] = []
    for command in commands:
        result = run_command(command)
        executed.append(" ".join(command))
        metadata.setdefault("command_results", []).append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        )
        if result.returncode != 0:
            return (
                RemediationStatus.FAILED,
                result.stderr.strip() or f"Command failed: {' '.join(command)}",
                commands,
                metadata,
            )

    return RemediationStatus.SUCCESS, "Runtime remediation completed.", commands, metadata


def save_json(path: str, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute runtime remediation actions")
    parser.add_argument("--findings", required=True, help="Findings JSON path")
    parser.add_argument("--decisions", required=True, help="Triage decisions JSON path")
    parser.add_argument(
        "--provider",
        default="openstack",
        help="Only remediate findings for this provider (default: openstack)",
    )
    parser.add_argument(
        "--output-events",
        default="artifacts/remediation/runtime_events.json",
        help="Where to write remediation events",
    )
    parser.add_argument(
        "--output-findings-after",
        default="artifacts/remediation/findings_after_runtime.json",
        help="Where to write findings after successful remediations",
    )
    parser.add_argument(
        "--approve-finding-id",
        action="append",
        default=[],
        help="Finding ID approved for manual remediation execution",
    )
    parser.add_argument(
        "--approve-all-manual",
        action="store_true",
        help="Approve all manual-review findings for demo execution",
    )
    parser.add_argument("--execute", action="store_true", help="Run provider commands for real")
    parser.add_argument(
        "--simulate-success",
        action="store_true",
        help="Do not call the provider; emit successful remediation events for demo pipelines",
    )
    parser.add_argument("--pipeline-source", default="manual-remediation")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings)
    decisions = load_decisions(args.decisions)
    decision_lookup = {str(item.get("finding_id") or ""): item for item in decisions}
    approved_ids = {item for item in args.approve_finding_id if item}

    events: List[Dict[str, Any]] = []
    findings_after = deepcopy(findings)
    by_id = {str(item.get("finding_id") or ""): item for item in findings_after}

    for finding in findings:
        if str(finding.get("provider") or "") != args.provider:
            continue
        if not finding.get("remediation_available"):
            continue

        finding_id = str(finding.get("finding_id") or "")
        decision = decision_lookup.get(
            finding_id,
            {
                "finding_id": finding_id,
                "recommendation": "manual_review",
                "created_at": utc_now_iso(),
            },
        )
        recommendation = str(decision.get("recommendation") or "manual_review")
        started_at = utc_now()
        manual_approval = recommendation != "auto_remediate"

        if recommendation == "ignore":
            continue

        if manual_approval and not approval_granted(
            finding,
            decision,
            approved_ids=approved_ids,
            approve_all_manual=args.approve_all_manual,
        ):
            event = create_event(
                finding=finding,
                decision=decision,
                status=RemediationStatus.PENDING,
                started_at=started_at,
                completed_at=None,
                manual_approval=False,
                dry_run=not args.execute,
                pipeline_source=args.pipeline_source,
                branch=args.branch,
                commit_sha=args.commit_sha,
                commands=[],
                notes="Manual approval required before runtime remediation.",
                metadata={"approval_required": True},
            )
            events.append(event.model_dump(mode="json"))
            continue

        status, notes, commands, metadata = execute_openstack_plan(
            finding,
            execute=args.execute,
            simulate_success=args.simulate_success,
        )
        completed_at = utc_now() if status != RemediationStatus.PENDING else None
        event = create_event(
            finding=finding,
            decision=decision,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            manual_approval=manual_approval,
            dry_run=not args.execute,
            pipeline_source=args.pipeline_source,
            branch=args.branch,
            commit_sha=args.commit_sha,
            commands=commands,
            notes=notes,
            metadata=metadata,
        )
        events.append(event.model_dump(mode="json"))

        if status == RemediationStatus.SUCCESS and completed_at is not None and finding_id in by_id:
            by_id[finding_id] = update_finding_after_success(by_id[finding_id], completed_at)

    save_json(args.output_events, events)
    save_json(args.output_findings_after, list(by_id.values()))
    logger.info("Wrote %s remediation events to %s", len(events), args.output_events)
    logger.info("Wrote post-remediation findings snapshot to %s", args.output_findings_after)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
