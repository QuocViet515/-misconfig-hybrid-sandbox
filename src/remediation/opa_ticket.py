"""
Evaluate IAM wildcard findings with OPA/Rego and generate a review ticket artifact.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import NAMESPACE_URL, uuid5

from ..models import RemediationEvent, RemediationStatus
from ..siem.publisher import load_decisions, load_findings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def stable_uuid(seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"opa-ticket:{seed}"))


def save_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def save_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def scenario_file(finding: Dict[str, Any]) -> str:
    metadata = finding.get("metadata") or {}
    return Path(str(metadata.get("file_path") or "")).name


def select_iam_wildcard_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    for finding in findings:
        if str(finding.get("provider") or "") != "aws":
            continue
        text = " ".join(
            str(value or "")
            for value in (
                finding.get("finding_code"),
                finding.get("title"),
                finding.get("description"),
                finding.get("resource_id"),
            )
        ).lower()
        if "wildcard" in text and "iam" in text:
            selected.append(finding)
    return selected


def fallback_review(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    reasons = [
        f"{finding.get('finding_code')} on {finding.get('resource_id')}"
        for finding in findings
    ]
    return {
        "review_required": bool(reasons),
        "risk": "HIGH" if reasons else "LOW",
        "ticket_priority": "P2" if reasons else "P4",
        "reasons": reasons,
        "engine": "python-fallback",
    }


def opa_available() -> bool:
    return shutil.which("opa") is not None


def run_opa(policy_path: Path, input_path: Path) -> Dict[str, Any]:
    result = subprocess.run(
        [
            "opa",
            "eval",
            "--format",
            "json",
            "--data",
            str(policy_path),
            "--input",
            str(input_path),
            "data.misconfig.iam_wildcard.review",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "opa eval failed")
    payload = json.loads(result.stdout)
    expressions = payload.get("result") or []
    if not expressions:
        raise RuntimeError("OPA returned no result")
    value = expressions[0].get("expressions", [{}])[0].get("value")
    if not isinstance(value, dict):
        raise RuntimeError("OPA returned unexpected value")
    value["engine"] = "opa"
    return value


def build_ticket_body(
    review: Dict[str, Any],
    findings: List[Dict[str, Any]],
    branch: str,
    commit_sha: str,
) -> str:
    lines = [
        "# IAM Wildcard Policy Review Required",
        "",
        f"- Branch: `{branch}`",
        f"- Commit: `{commit_sha}`",
        f"- Risk: `{review.get('risk', 'UNKNOWN')}`",
        f"- Priority: `{review.get('ticket_priority', 'P2')}`",
        f"- Policy engine: `{review.get('engine', 'unknown')}`",
        "",
        "## Findings",
        "",
    ]
    for finding in findings:
        lines.append(
            f"- `{finding.get('finding_code')}` on `{finding.get('resource_id')}`: {finding.get('title')}"
        )
    lines.extend(
        [
            "",
            "## Review Guidance",
            "",
        ]
    )
    for reason in review.get("reasons", []):
        lines.append(f"- {reason}")
    lines.extend(
        [
            "",
            "Do not auto-remediate IAM wildcard policies without owner approval.",
            "Review least-privilege replacements before applying any change.",
            "",
        ]
    )
    return "\n".join(lines)


def maybe_create_github_issue(repo: str, token: str, title: str, body: str) -> Optional[Dict[str, Any]]:
    payload = json.dumps(
        {
            "title": title,
            "body": body,
            "labels": ["security", "manual-review"],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/issues",
        data=payload,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "misconfig-auto-remediate",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        logger.error("Failed to create GitHub issue: %s", exc.read().decode("utf-8", "ignore"))
    except urllib.error.URLError as exc:
        logger.error("Failed to create GitHub issue: %s", exc)
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate IAM wildcard findings and generate review ticket artifacts")
    parser.add_argument("--findings", required=True, help="Findings JSON path")
    parser.add_argument("--decisions", required=True, help="Triage decisions JSON path")
    parser.add_argument(
        "--policy-file",
        default="policy/iam_wildcard.rego",
        help="OPA/Rego policy file path",
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/tickets/iam_wildcard_review",
        help="Where to write ticket artifacts",
    )
    parser.add_argument("--pipeline-source", default="opa-iam-review")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--create-github-issue", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings)
    decisions = load_decisions(args.decisions)
    decision_lookup = {str(item.get("finding_id") or ""): item for item in decisions}

    selected = select_iam_wildcard_findings(findings)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    input_payload = {
        "generated_at": utc_now().isoformat().replace("+00:00", "Z"),
        "findings": selected,
    }
    input_path = output_dir / "input.json"
    save_json(input_path, input_payload)

    if not selected:
        review = fallback_review([])
    elif opa_available():
        review = run_opa(Path(args.policy_file), input_path)
    else:
        review = fallback_review(selected)

    review_path = output_dir / "opa_result.json"
    save_json(review_path, review)

    ticket_body = build_ticket_body(review, selected, args.branch, args.commit_sha)
    ticket_path = output_dir / "SECURITY_REVIEW_TICKET.md"
    save_text(ticket_path, ticket_body)

    issue_response = None
    if review.get("review_required") and args.create_github_issue and args.repo and args.token:
        issue_response = maybe_create_github_issue(
            repo=args.repo,
            token=args.token,
            title="Security review required: IAM wildcard policy findings",
            body=ticket_body,
        )
        if issue_response:
            save_json(output_dir / "github_issue.json", issue_response)

    now = utc_now()
    events: List[Dict[str, Any]] = []
    for finding in selected:
        finding_id = str(finding.get("finding_id") or "")
        decision = decision_lookup.get(finding_id, {})
        event = RemediationEvent(
            event_id=stable_uuid(f"{finding_id}:{ticket_path}"),
            finding_id=finding_id,
            finding_code=str(finding.get("finding_code") or ""),
            provider=str(finding.get("provider") or ""),
            resource_id=str(finding.get("resource_id") or ""),
            action_kind="review_ticket",
            recommendation=str(decision.get("recommendation") or "manual_review"),
            status=RemediationStatus.SUCCESS,
            started_at=now,
            completed_at=now,
            duration_seconds=0.0,
            manual_approval=True,
            dry_run=True,
            pipeline_source=args.pipeline_source,
            branch=args.branch,
            commit_sha=args.commit_sha,
            notes="OPA review ticket generated for IAM wildcard findings.",
            metadata={
                "policy_file": args.policy_file,
                "ticket_path": str(ticket_path),
                "review_result": review,
                "github_issue_url": (issue_response or {}).get("html_url"),
            },
        )
        events.append(event.model_dump(mode="json"))

    save_json(output_dir / "review_events.json", events)
    logger.info("Generated IAM review artifacts in %s", output_dir)
    logger.info("Selected %s IAM wildcard findings", len(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
