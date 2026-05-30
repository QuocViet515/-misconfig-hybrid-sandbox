"""
Detect generic IaC drift by comparing live cloud state against Terraform state and code.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from uuid import NAMESPACE_URL, uuid5

from ..models import NormalizedFinding, SeverityLevel


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def stable_uuid(seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"iac-drift:{seed}"))


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


def ensure_local_state(terraform_dir: Path, output_dir: Path, provider: str, stack_name: str) -> None:
    state_path = terraform_dir / "terraform.tfstate"
    if state_path.exists():
        return

    summary = {
        "provider": provider,
        "stack_name": stack_name,
        "terraform_dir": str(terraform_dir),
        "state_present": False,
        "drift_detected": None,
        "change_count": 0,
        "error": (
            "No local terraform.tfstate was restored for this stack. "
            "Run the hybrid delivery workflow first, or persist the Terraform state "
            "with scripts/sync_terraform_state.sh before running drift detection."
        ),
    }
    save_json(output_dir / "summary.json", summary)
    raise RuntimeError(summary["error"])


def iter_drift_changes(plan: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for item in plan.get("resource_changes", []) if isinstance(plan, dict) else []:
        if not isinstance(item, dict):
            continue
        change = item.get("change") or {}
        actions = change.get("actions") or []
        if actions == ["no-op"]:
            continue
        yield item


def summarize_changes(plan: Dict[str, Any]) -> Dict[str, Any]:
    resource_changes = list(iter_drift_changes(plan))
    by_action: Dict[str, int] = {}
    summarized = []
    for item in resource_changes:
        address = str(item.get("address") or "")
        change = item.get("change") or {}
        actions = change.get("actions") or []
        action_key = "/".join(actions) if actions else "unknown"
        by_action[action_key] = by_action.get(action_key, 0) + 1
        summarized.append(
            {
                "address": address,
                "resource_type": str(item.get("type") or ""),
                "actions": actions,
                "before": change.get("before"),
                "after": change.get("after"),
            }
        )
    return {
        "drift_detected": bool(resource_changes),
        "change_count": len(resource_changes),
        "by_action": by_action,
        "resource_changes": summarized,
    }


def build_findings(
    *,
    provider: str,
    stack_name: str,
    region: str,
    plan_summary: Dict[str, Any],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    now = utc_now()
    for item in plan_summary.get("resource_changes", []):
        address = str(item.get("address") or "unknown")
        resource_type = str(item.get("resource_type") or "terraform_resource")
        actions = item.get("actions") or []
        title = f"Terraform drift detected for {address}"
        description = (
            f"Terraform refresh-only plan detected drift on `{address}` in stack `{stack_name}` "
            f"with actions `{', '.join(actions) if actions else 'unknown'}`."
        )
        finding = NormalizedFinding(
            finding_id=stable_uuid(f"{provider}:{stack_name}:{address}"),
            finding_code="IAC_DRIFT_DETECTED",
            scanner="terraform_refresh_only",
            provider=provider,
            severity=SeverityLevel.MEDIUM,
            title=title,
            description=description,
            resource_type=resource_type,
            resource_id=address,
            resource_name=address,
            region=region or None,
            risk_category="drift",
            remediation_available=False,
            remediation_type="manual",
            detected_at=now,
            last_seen_at=now,
            metadata={
                "stack_name": stack_name,
                "actions": actions,
                "before": item.get("before"),
                "after": item.get("after"),
            },
            tags={"provider": provider, "stack": stack_name},
        )
        findings.append(finding.model_dump(mode="json"))
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect IaC drift with terraform plan -refresh-only")
    parser.add_argument("--terraform-dir", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--stack-name", default="")
    parser.add_argument("--region", default="")
    parser.add_argument("--output-dir", default="artifacts/drift/generic")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    terraform_dir = Path(args.terraform_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    terraform = resolve_tool("terraform")
    stack_name = args.stack_name or terraform_dir.name

    ensure_local_state(terraform_dir, output_dir, args.provider, stack_name)
    run_checked([terraform, "init", "-input=false"], cwd=terraform_dir)

    plan_path = output_dir / f"{stack_name}_drift.tfplan"
    plan_result = run_command(
        [
            terraform,
            "plan",
            "-refresh-only",
            "-input=false",
            "-detailed-exitcode",
            f"-out={plan_path}",
        ],
        cwd=terraform_dir,
    )
    if plan_result.returncode not in {0, 2}:
        raise RuntimeError(plan_result.stderr.strip() or plan_result.stdout.strip() or "terraform refresh-only plan failed")

    plan_json = json.loads(run_checked([terraform, "show", "-json", str(plan_path)], cwd=terraform_dir).stdout)
    summary = summarize_changes(plan_json)
    summary.update(
        {
            "provider": args.provider,
            "stack_name": stack_name,
            "terraform_dir": str(terraform_dir),
            "state_present": True,
            "plan_exit_code": plan_result.returncode,
        }
    )

    findings = build_findings(
        provider=args.provider,
        stack_name=stack_name,
        region=args.region,
        plan_summary=summary,
    )

    save_json(output_dir / "plan.json", plan_json)
    save_json(output_dir / "summary.json", summary)
    save_json(output_dir / "findings.json", findings)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
