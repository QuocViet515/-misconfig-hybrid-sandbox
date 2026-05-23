"""
Detect and reconcile the M5 runtime drift scenario with Terraform.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import NAMESPACE_URL, uuid5

from ..models import RemediationEvent, RemediationStatus

REPO_ROOT = Path(__file__).resolve().parents[2]


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def stable_uuid(seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"drift-reconcile:{seed}"))


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run_command(command: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )


def run_checked(command: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    result = run_command(command, cwd=cwd)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"Command failed: {' '.join(command)}")
    return result


def resolve_tool(binary: str) -> str:
    resolved = shutil.which(binary)
    if not resolved:
        raise RuntimeError(f"Required tool not found on PATH: {binary}")
    return resolved


def resolve_sg_id(terraform_dir: Path, region: str, project_prefix: str, explicit_sg_id: str) -> str:
    if explicit_sg_id:
        return explicit_sg_id

    terraform = resolve_tool("terraform")
    output = run_command([terraform, "output", "-raw", "m5_intended_sg_id"], cwd=terraform_dir)
    if output.returncode == 0 and output.stdout.strip():
        return output.stdout.strip()

    aws = resolve_tool("aws")
    describe = run_checked(
        [
            aws,
            "ec2",
            "describe-security-groups",
            "--region",
            region,
            "--filters",
            "Name=tag:Scenario,Values=M5-IaCDrift",
            f"Name=tag:Name,Values={project_prefix}-m5-intended-sg",
            "--query",
            "SecurityGroups[0].GroupId",
            "--output",
            "text",
        ]
    )
    sg_id = describe.stdout.strip()
    if sg_id and sg_id != "None":
        return sg_id
    raise RuntimeError(f"Unable to resolve the M5 security group for prefix {project_prefix}")


def simulate_drift(region: str, sg_id: str) -> List[Dict[str, Any]]:
    aws = resolve_tool("aws")
    results: List[Dict[str, Any]] = []
    for port in (22, 3306):
        command = [
            aws,
            "ec2",
            "authorize-security-group-ingress",
            "--region",
            region,
            "--group-id",
            sg_id,
            "--protocol",
            "tcp",
            "--port",
            str(port),
            "--cidr",
            "0.0.0.0/0",
        ]
        result = run_command(command)
        duplicate = "InvalidPermission.Duplicate" in (result.stderr or "")
        if result.returncode not in {0} and not duplicate:
            raise RuntimeError(result.stderr.strip() or f"Failed to create drift on port {port}")
        results.append(
            {
                "command": command,
                "returncode": result.returncode,
                "duplicate_rule": duplicate,
                "stderr": result.stderr,
            }
        )
    return results


def summarize_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    resource_changes = plan.get("resource_changes", []) if isinstance(plan, dict) else []
    relevant_changes = []
    for item in resource_changes:
        address = str(item.get("address") or "")
        if not address.startswith("aws_security_group.m5_intended_sg"):
            continue
        change = item.get("change") or {}
        relevant_changes.append(
            {
                "address": address,
                "actions": change.get("actions", []),
                "before": change.get("before"),
                "after": change.get("after"),
            }
        )

    drift_detected = bool(relevant_changes)
    return {
        "drift_detected": drift_detected,
        "change_count": len(relevant_changes),
        "resource_changes": relevant_changes,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect and reconcile the M5 Terraform drift scenario")
    parser.add_argument("--terraform-dir", default="iac/terraform")
    parser.add_argument("--region", default="ap-southeast-1")
    parser.add_argument("--project-prefix", default="threat-demo")
    parser.add_argument("--sg-id", default="")
    parser.add_argument("--simulate-drift", action="store_true", help="Create the M5 drift via AWS CLI before running terraform plan")
    parser.add_argument("--execute", action="store_true", help="Apply the generated Terraform plan to reconcile drift")
    parser.add_argument("--pipeline-source", default="m5-drift-reconcile")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--output-dir", default="artifacts/drift/m5")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    terraform_dir = Path(args.terraform_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    terraform = resolve_tool("terraform")
    sg_id = resolve_sg_id(terraform_dir, args.region, args.project_prefix, args.sg_id)
    drift_actions: List[Dict[str, Any]] = []
    if args.simulate_drift:
        drift_actions = simulate_drift(args.region, sg_id)
        save_json(output_dir / "simulate_drift.json", drift_actions)

    run_checked([terraform, "init", "-input=false", "-backend=false"], cwd=terraform_dir)

    plan_path = output_dir / "m5_drift.tfplan"
    plan_result = run_command(
        [
            terraform,
            "plan",
            "-input=false",
            "-detailed-exitcode",
            "-target=aws_security_group.m5_intended_sg",
            f"-out={plan_path}",
        ],
        cwd=terraform_dir,
    )
    if plan_result.returncode not in {0, 2}:
        raise RuntimeError(plan_result.stderr.strip() or plan_result.stdout.strip() or "terraform plan failed")

    plan_json = json.loads(run_checked([terraform, "show", "-json", str(plan_path)], cwd=terraform_dir).stdout)
    summary = summarize_plan(plan_json)
    summary.update(
        {
            "sg_id": sg_id,
            "terraform_dir": str(terraform_dir),
            "plan_exit_code": plan_result.returncode,
        }
    )
    save_json(output_dir / "plan.json", plan_json)
    save_json(output_dir / "summary.json", summary)

    events: List[Dict[str, Any]] = []
    started_at = utc_now()
    status = RemediationStatus.PENDING if summary["drift_detected"] else RemediationStatus.SUCCESS
    notes = "Terraform drift detected for M5; remediation plan generated."

    if args.execute and summary["drift_detected"]:
        run_checked([terraform, "apply", "-auto-approve", str(plan_path)], cwd=terraform_dir)
        verify_result = run_command(
            [
                terraform,
                "plan",
                "-input=false",
                "-detailed-exitcode",
                "-target=aws_security_group.m5_intended_sg",
            ],
            cwd=terraform_dir,
        )
        if verify_result.returncode not in {0, 2}:
            raise RuntimeError(verify_result.stderr.strip() or verify_result.stdout.strip() or "post-apply terraform plan failed")
        verify_payload = {
            "returncode": verify_result.returncode,
            "stdout": verify_result.stdout,
            "stderr": verify_result.stderr,
        }
        save_json(output_dir / "post_apply_verification.json", verify_payload)
        status = RemediationStatus.SUCCESS if verify_result.returncode == 0 else RemediationStatus.PENDING
        notes = (
            "Terraform reconciled the M5 drift and verification returned no remaining changes."
            if status == RemediationStatus.SUCCESS
            else "Terraform apply completed, but subsequent plan still reports remaining drift."
        )

    completed_at = utc_now() if status != RemediationStatus.PENDING or args.execute else None
    event = RemediationEvent(
        event_id=stable_uuid(f"{sg_id}:{args.pipeline_source}:{args.commit_sha}:{args.execute}:{args.simulate_drift}"),
        finding_id=stable_uuid(f"m5-finding:{sg_id}"),
        finding_code="M5_IAC_DRIFT",
        provider="aws",
        resource_id=sg_id,
        action_kind="drift_reconcile",
        recommendation="auto_remediate",
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=round((completed_at - started_at).total_seconds(), 3) if completed_at else None,
        manual_approval=False,
        dry_run=not args.execute,
        pipeline_source=args.pipeline_source,
        branch=args.branch,
        commit_sha=args.commit_sha,
        command=[
            f"{terraform} plan -target=aws_security_group.m5_intended_sg -out={plan_path}",
            f"{terraform} show -json {plan_path}",
        ],
        notes=notes,
        metadata={
            "sg_id": sg_id,
            "drift_detected": summary["drift_detected"],
            "change_count": summary["change_count"],
            "simulate_drift": args.simulate_drift,
        },
    )
    events.append(event.model_dump(mode="json"))
    save_json(output_dir / "reconcile_events.json", events)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
