"""
Generate PR-ready IaC remediation artifacts from normalized findings.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple
from uuid import NAMESPACE_URL, uuid5
import difflib

from ..models import RemediationEvent, RemediationStatus
from ..siem.publisher import load_decisions, load_findings


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def stable_uuid(seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"iac-pr:{seed}"))


def save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def save_json(path: Path, payload: Any) -> None:
    save_text(path, json.dumps(payload, indent=2) + "\n")


def remove_resource_block(text: str, resource_type: str, resource_name: str) -> str:
    marker = f'resource "{resource_type}" "{resource_name}" {{'
    start = text.find(marker)
    if start == -1:
        return text

    brace_count = 0
    end = start
    opened = False
    for idx in range(start, len(text)):
        char = text[idx]
        if char == "{":
            brace_count += 1
            opened = True
        elif char == "}":
            brace_count -= 1
            if opened and brace_count == 0:
                end = idx + 1
                break
    return text[:start].rstrip() + "\n\n" + text[end:].lstrip("\n")


def ensure_admin_cidr_variable(text: str) -> str:
    if 'variable "admin_cidr_blocks"' in text:
        return text
    addition = """
variable "admin_cidr_blocks" {
  description = "Approved administrative CIDR blocks for management access"
  type        = list(string)
  default     = ["10.0.0.0/24"]
}
"""
    return text.rstrip() + "\n\n" + addition.lstrip()


def run_optional_command(command: List[str], cwd: Path) -> Tuple[int, str, str]:
    result = subprocess.run(
        command,
        cwd=str(cwd),
        check=False,
        text=True,
        capture_output=True,
    )
    return result.returncode, result.stdout, result.stderr


def resolve_tool(binary: str) -> str | None:
    local_candidate = Path(sys.executable).with_name(binary)
    if local_candidate.exists():
        return str(local_candidate)
    return shutil.which(binary)


def fix_m1_public_s3(text: str) -> str:
    fixed = text
    fixed = fixed.replace('object_ownership = "BucketOwnerPreferred"', 'object_ownership = "BucketOwnerEnforced"')
    fixed = fixed.replace("block_public_acls       = false", "block_public_acls       = true")
    fixed = fixed.replace("block_public_policy     = false", "block_public_policy     = true")
    fixed = fixed.replace("ignore_public_acls      = false", "ignore_public_acls      = true")
    fixed = fixed.replace("restrict_public_buckets = false", "restrict_public_buckets = true")
    fixed = fixed.replace('acl    = "public-read"', 'acl    = "private"')
    fixed = remove_resource_block(fixed, "aws_s3_bucket_acl", "m1_public_acl")
    fixed = remove_resource_block(fixed, "aws_s3_bucket_policy", "m1_public_policy")
    return fixed


def fix_m2_wide_open_sg(text: str) -> str:
    fixed = text
    fixed = fixed.replace(
        'cidr_blocks = ["0.0.0.0/0"] #  Toàn bộ IPv4',
        'cidr_blocks = var.admin_cidr_blocks #  Chỉ cho phép quản trị từ CIDR tin cậy',
        2,
    )
    dangerous_ingress = """
  #  Mở ALL traffic inbound
  ingress {
    description = "All traffic from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] #  Tất cả port, tất cả protocol
  }
"""
    fixed = fixed.replace(dangerous_ingress, "")
    return fixed


def fix_m4_unencrypted_storage(text: str) -> str:
    fixed = text
    fixed = fixed.replace("encrypted         = false", "encrypted         = true")
    fixed = fixed.replace("storage_encrypted = false", "storage_encrypted = true")
    fixed = fixed.replace(
        """resource "aws_s3_bucket" "m4_unencrypted_bucket" {
  bucket        = "${var.project_prefix}-m4-unencrypted-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name     = "${var.project_prefix}-m4-unencrypted-bucket"
    Scenario = "M4-UnencryptedStorage"
    Risk     = "HIGH"
  }
}
""",
        """resource "aws_s3_bucket" "m4_unencrypted_bucket" {
  bucket        = "${var.project_prefix}-m4-unencrypted-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name     = "${var.project_prefix}-m4-unencrypted-bucket"
    Scenario = "M4-UnencryptedStorage"
    Risk     = "HIGH"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "m4_bucket_sse" {
  bucket = aws_s3_bucket.m4_unencrypted_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
""",
    )
    fixed = fixed.replace(
        """resource "aws_s3_object" "m4_unencrypted_object" {
  bucket  = aws_s3_bucket.m4_unencrypted_bucket.id
  key     = "secrets/database_credentials.json"
  content = jsonencode({
    host     = "prod-db.internal.example.com"
    port     = 5432
    username = "admin"
    password = "SuperSecretP@ss123!" #  Password hardcoded
    database = "production"
  })
  #  Không có server_side_encryption → lưu plaintext

  tags = {
    Classification = "CONFIDENTIAL"
  }
}
""",
        """resource "aws_s3_object" "m4_unencrypted_object" {
  bucket  = aws_s3_bucket.m4_unencrypted_bucket.id
  key     = "secrets/database_credentials.json"
  content = jsonencode({
    host     = "prod-db.internal.example.com"
    port     = 5432
    username = "admin"
    password = "SuperSecretP@ss123!" #  Password hardcoded
    database = "production"
  })
  server_side_encryption = "AES256"

  tags = {
    Classification = "CONFIDENTIAL"
  }
}
""",
    )
    return fixed


SUPPORTED_FIXERS = {
    "m1_public_s3.tf": fix_m1_public_s3,
    "m2_wide_open_sg.tf": fix_m2_wide_open_sg,
    "m4_unencrypted_storage.tf": fix_m4_unencrypted_storage,
}

TARGETED_FINDING_CODES = {
    "m1_public_s3.tf": {
        "CKV_AWS_20",
        "CKV_AWS_53",
        "CKV_AWS_54",
        "CKV_AWS_55",
        "CKV_AWS_56",
        "CKV_AWS_70",
        "CKV2_AWS_65",
    },
    "m2_wide_open_sg.tf": {
        "CKV_AWS_24",
        "CKV_AWS_25",
        "CKV_AWS_260",
        "CKV_AWS_277",
    },
    "m4_unencrypted_storage.tf": {
        "CKV_AWS_3",
        "CKV_AWS_16",
    },
}


def post_validation(terraform_dir: Path) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}

    terraform = resolve_tool("terraform")
    if terraform:
        code, stdout, stderr = run_optional_command([terraform, "fmt", "-recursive"], terraform_dir)
        summary["terraform_fmt"] = {
            "available": True,
            "returncode": code,
            "stdout": stdout,
            "stderr": stderr,
        }
    else:
        summary["terraform_fmt"] = {"available": False}

    checkov = resolve_tool("checkov")
    if checkov:
        code, stdout, stderr = run_optional_command(
            [checkov, "-d", ".", "--framework", "terraform", "-o", "json"],
            terraform_dir,
        )
        payload: Dict[str, Any] = {}
        if stdout.strip():
            try:
                parsed = json.loads(stdout)
                payload = {
                    "failed_checks": len(parsed.get("results", {}).get("failed_checks", [])),
                    "passed_checks": len(parsed.get("results", {}).get("passed_checks", [])),
                }
            except json.JSONDecodeError:
                payload = {"raw_stdout": stdout}
        summary["checkov"] = {
            "available": True,
            "returncode": code,
            "stdout_summary": payload,
            "stderr": stderr,
        }
    else:
        summary["checkov"] = {"available": False}

    return summary


def generate_events(
    findings: List[Dict[str, Any]],
    decision_lookup: Dict[str, Dict[str, Any]],
    addressed_ids: set[str],
    *,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
    pr_dir: Path,
    patch_path: Path,
) -> List[Dict[str, Any]]:
    started_at = utc_now()
    completed_at = utc_now()
    events: List[Dict[str, Any]] = []
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "")
        if finding_id not in addressed_ids:
            continue
        decision = decision_lookup.get(finding_id, {})
        event = RemediationEvent(
            event_id=stable_uuid(f"iac-pr:{finding_id}:{patch_path}"),
            finding_id=finding_id,
            finding_code=str(finding.get("finding_code") or ""),
            provider=str(finding.get("provider") or ""),
            resource_id=str(finding.get("resource_id") or ""),
            action_kind="iac_pr_prepare",
            recommendation=str(decision.get("recommendation") or "manual_review"),
            status=RemediationStatus.SUCCESS,
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=round((completed_at - started_at).total_seconds(), 3),
            manual_approval=False,
            dry_run=True,
            pipeline_source=pipeline_source,
            branch=branch,
            commit_sha=commit_sha,
            patch_path=str(patch_path),
            pr_artifact_dir=str(pr_dir),
            notes="Generated PR-ready Terraform remediation artifact bundle.",
            metadata={
                "file_path": finding.get("metadata", {}).get("file_path"),
                "fix_bundle": str(pr_dir),
            },
        )
        events.append(event.model_dump(mode="json"))
    return events


def build_pr_body(
    *,
    branch_name: str,
    terraform_path_label: str,
    files_changed: List[str],
    supported_findings: List[Dict[str, Any]],
    unsupported_findings: List[Dict[str, Any]],
) -> str:
    lines = [
        "# Automated Terraform Remediation Proposal",
        "",
        f"- Suggested branch: `{branch_name}`",
        f"- Files changed: `{len(files_changed)}`",
        f"- Supported findings addressed: `{len(supported_findings)}`",
        f"- Findings still manual: `{len(unsupported_findings)}`",
        "",
        "## Included fixes",
        "",
    ]
    for finding in supported_findings:
        lines.append(
            f"- `{finding['finding_code']}` on `{finding['resource_id']}` from `{finding['metadata'].get('file_path')}`"
        )
    lines.extend(["", "## Remaining manual follow-up", ""])
    if unsupported_findings:
        for finding in unsupported_findings[:20]:
            lines.append(
                f"- `{finding['finding_code']}` on `{finding['resource_id']}`"
                f" (`{finding['metadata'].get('file_path', 'unknown file')}`)"
            )
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Validation",
            "",
            "- Review generated patch and run `terraform fmt -recursive`.",
            f"- Run `terraform validate` in `{terraform_path_label}`.",
            "- Re-run Checkov before merging.",
        ]
    )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate PR-ready IaC remediation artifacts")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--terraform-dir", default="iac/aws")
    parser.add_argument("--output-dir", default="artifacts/iac_pr")
    parser.add_argument("--run-label", default="")
    parser.add_argument("--pipeline-source", default="iac-pr-prep")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings)
    decisions = load_decisions(args.decisions)
    decision_lookup = {str(item.get("finding_id") or ""): item for item in decisions}

    terraform_dir = Path(args.terraform_dir)
    output_root = Path(args.output_dir)
    run_label = args.run_label or utc_now().strftime("%Y%m%dT%H%M%SZ")
    run_dir = output_root / run_label
    if run_dir.exists():
        shutil.rmtree(run_dir)
    terraform_rel = Path(args.terraform_dir).as_posix().strip("/")
    fixed_dir = run_dir / "fixed_tree" / terraform_rel
    shutil.copytree(terraform_dir, fixed_dir)

    supported_findings: List[Dict[str, Any]] = []
    unsupported_findings: List[Dict[str, Any]] = []
    addressed_ids: set[str] = set()
    files_changed: List[str] = []
    diffs: List[str] = []

    findings_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        if str(finding.get("remediation_type") or "") != "pr":
            continue
        file_path = str(finding.get("metadata", {}).get("file_path") or "").lstrip("/")
        if not file_path:
            unsupported_findings.append({**finding, "reason": "missing_file_path"})
            continue
        findings_by_file.setdefault(file_path, []).append(finding)

    variables_path = fixed_dir / "variables.tf"
    variables_before = variables_path.read_text(encoding="utf-8")
    variables_after = ensure_admin_cidr_variable(variables_before)
    if variables_after != variables_before:
        save_text(variables_path, variables_after)
        files_changed.append("variables.tf")
        diffs.append(
            "".join(
                difflib.unified_diff(
                    variables_before.splitlines(keepends=True),
                    variables_after.splitlines(keepends=True),
                    fromfile=f"a/{terraform_rel}/variables.tf",
                    tofile=f"b/{terraform_rel}/variables.tf",
                )
            )
        )

    for relative_path, file_findings in findings_by_file.items():
        fixer = SUPPORTED_FIXERS.get(Path(relative_path).name)
        if fixer is None:
            for finding in file_findings:
                unsupported_findings.append({**finding, "reason": "unsupported_file"})
            continue

        targeted_codes = TARGETED_FINDING_CODES.get(Path(relative_path).name, set())
        targeted_findings = [
            finding for finding in file_findings if str(finding.get("finding_code") or "") in targeted_codes
        ]
        untargeted_findings = [
            finding for finding in file_findings if str(finding.get("finding_code") or "") not in targeted_codes
        ]
        for finding in untargeted_findings:
            unsupported_findings.append({**finding, "reason": "untargeted_check"})
        if not targeted_findings:
            continue

        target_path = fixed_dir / Path(relative_path).name
        before = target_path.read_text(encoding="utf-8")
        after = fixer(before)
        if after == before:
            for finding in targeted_findings:
                unsupported_findings.append({**finding, "reason": "no_change_generated"})
            continue

        save_text(target_path, after)
        files_changed.append(Path(relative_path).name)
        diffs.append(
            "".join(
                difflib.unified_diff(
                    before.splitlines(keepends=True),
                    after.splitlines(keepends=True),
                    fromfile=f"a/{terraform_rel}/{Path(relative_path).name}",
                    tofile=f"b/{terraform_rel}/{Path(relative_path).name}",
                )
            )
        )
        for finding in targeted_findings:
            supported_findings.append(finding)
            addressed_ids.add(str(finding.get("finding_id") or ""))

    patch_path = run_dir / "terraform_fix.patch"
    save_text(patch_path, "".join(diffs))
    validation = post_validation(fixed_dir)
    save_json(run_dir / "validation.json", validation)

    branch_name = f"autofix/{utc_now().strftime('%Y%m%d-%H%M%S')}"
    pr_body = build_pr_body(
        branch_name=branch_name,
        terraform_path_label=terraform_rel,
        files_changed=files_changed,
        supported_findings=supported_findings,
        unsupported_findings=unsupported_findings,
    )
    pr_body_path = run_dir / "PR_BODY.md"
    save_text(pr_body_path, pr_body)

    summary = {
        "generated_at": utc_now_iso(),
        "suggested_branch": branch_name,
        "terraform_source": str(terraform_dir),
        "artifact_dir": str(run_dir),
        "files_changed": files_changed,
        "supported_findings_count": len(supported_findings),
        "unsupported_findings_count": len(unsupported_findings),
        "supported_finding_ids": sorted(addressed_ids),
        "patch_file": str(patch_path),
        "pr_body_file": str(pr_body_path),
        "validation_file": str(run_dir / "validation.json"),
        "validation": validation,
    }
    summary_path = run_dir / "summary.json"
    save_json(summary_path, summary)

    events = generate_events(
        supported_findings,
        decision_lookup,
        addressed_ids,
        pipeline_source=args.pipeline_source,
        branch=args.branch,
        commit_sha=args.commit_sha,
        pr_dir=run_dir,
        patch_path=patch_path,
    )
    events_path = run_dir / "iac_pr_events.json"
    save_json(events_path, events)

    unsupported_path = run_dir / "unsupported_findings.json"
    save_json(unsupported_path, unsupported_findings)

    print(json.dumps({**summary, "events_file": str(events_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
