#!/usr/bin/env python3
"""Seed or purge a small mock dataset for the Kibana demo dashboard."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.request
from typing import Dict, Iterable, List, Tuple


DEFAULT_SCHEME = "http"
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 9200
PIPELINE_SOURCE = "mock-dashboard-1"
DOC_PREFIX = "mock-dashboard-1"


def iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_indices(index_date: str) -> Tuple[str, str]:
    return (f"misconfig-findings-{index_date}", f"misconfig-triage-{index_date}")


def request(method: str, url: str, payload: bytes | None = None) -> Dict:
    req = urllib.request.Request(url, method=method, data=payload)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"{method} {url} failed: {exc.code} {body}") from exc


def bulk_request(base_url: str, actions: List[Dict], refresh: str = "wait_for") -> Dict:
    lines = [json.dumps(action) for action in actions]
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    url = f"{base_url}/_bulk?refresh={refresh}"
    req = urllib.request.Request(url, method="PUT", data=payload)
    req.add_header("Content-Type", "application/x-ndjson")
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"PUT {url} failed: {exc.code} {body}") from exc


def mock_findings(timestamp: str) -> Iterable[Dict]:
    cases = [
        (
            "checkov",
            "aws",
            "critical",
            "s3-bucket",
            "Public S3 bucket",
            "CKV_AWS_20",
            "aws-s3-public",
            True,
            "terraform_patch",
        ),
        (
            "checkov",
            "aws",
            "high",
            "security-group",
            "Security group open to world",
            "CKV_AWS_24",
            "aws-sg-open",
            True,
            "terraform_patch",
        ),
        (
            "checkov",
            "aws",
            "medium",
            "iam-user",
            "Access key older than 90 days",
            "CKV_AWS_273",
            "aws-key-rotation",
            False,
            "manual_runbook",
        ),
        (
            "checkov",
            "aws",
            "low",
            "cloudtrail",
            "Trail not encrypted",
            "CKV_AWS_252",
            "aws-trail-encryption",
            True,
            "terraform_patch",
        ),
        (
            "openstack-audit",
            "openstack",
            "critical",
            "security-group",
            "OpenStack security group allows 0.0.0.0/0",
            "OPENSTACK_SG_WIDE_OPEN",
            "os-sg-open-ssh",
            True,
            "openstack_cli",
        ),
        (
            "openstack-audit",
            "openstack",
            "high",
            "swift-container",
            "Swift container is publicly readable",
            "OPENSTACK_SWIFT_PUBLIC",
            "os-swift-public",
            True,
            "openstack_cli",
        ),
        (
            "openstack-audit",
            "openstack",
            "medium",
            "project",
            "Project has no quota cap",
            "OPENSTACK_PROJECT_NO_QUOTA",
            "os-project-no-quota",
            False,
            "manual_runbook",
        ),
        (
            "openstack-audit",
            "openstack",
            "low",
            "identity-user",
            "User missing MFA policy evidence",
            "OPENSTACK_USER_NO_MFA",
            "os-user-no-mfa",
            False,
            "manual_runbook",
        ),
    ]
    for index, (
        scanner,
        provider,
        severity,
        resource_type,
        title,
        finding_code,
        resource_id,
        remediation_available,
        remediation_type,
    ) in enumerate(cases, start=1):
        finding_uid = f"{DOC_PREFIX}:finding:{index:02d}"
        yield {
            "_id": finding_uid,
            "@timestamp": timestamp,
            "doc_kind": "finding",
            "detected_at": timestamp,
            "last_seen_at": timestamp,
            "ingested_at": timestamp,
            "title": title,
            "description": f"Mock finding for dashboard validation: {title}.",
            "severity": severity,
            "provider": provider,
            "scanner": scanner,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "finding_code": finding_code,
            "finding_id": finding_uid,
            "finding_uid": finding_uid,
            "pipeline_source": PIPELINE_SOURCE,
            "remediation_available": remediation_available,
            "remediation_type": remediation_type,
            "status": "OPEN" if severity in {"critical", "high", "medium"} else "ACKNOWLEDGED",
            "git_branch": "mock-dashboard-demo",
            "git_commit": "mock0001",
            "git": {"branch": "mock-dashboard-demo", "commit": "mock0001"},
            "cis_controls": ["CIS-1.1", "CIS-4.2"] if provider == "aws" else ["CIS-5.1", "CIS-6.2"],
            "metadata": {
                "mock": True,
                "dataset": PIPELINE_SOURCE,
                "owner": "codex",
            },
        }


def mock_decisions(timestamp: str) -> Iterable[Dict]:
    recommendations = [
        "auto_remediate",
        "manual_review",
        "manual_review",
        "manual_review",
        "auto_remediate",
        "manual_review",
        "manual_review",
        "ignore",
    ]
    for index, recommendation in enumerate(recommendations, start=1):
        decision_uid = f"{DOC_PREFIX}:decision:{index:02d}"
        finding_uid = f"{DOC_PREFIX}:finding:{index:02d}"
        yield {
            "_id": decision_uid,
            "@timestamp": timestamp,
            "doc_kind": "triage_decision",
            "ingested_at": timestamp,
            "decision_id": decision_uid,
            "finding_uid": finding_uid,
            "finding_id": finding_uid,
            "recommendation": recommendation,
            "confidence": 0.95 if recommendation == "auto_remediate" else 0.7,
            "rationale": f"Mock triage decision for {finding_uid}.",
            "pipeline_source": PIPELINE_SOURCE,
            "git": {"branch": "mock-dashboard-demo", "commit": "mock0001"},
            "metadata": {
                "mock": True,
                "dataset": PIPELINE_SOURCE,
                "owner": "codex",
            },
        }


def bulk_index_actions(findings_index: str, triage_index: str, timestamp: str) -> List[Dict]:
    actions: List[Dict] = []
    for document in mock_findings(timestamp):
        actions.append({"index": {"_index": findings_index, "_id": document.pop("_id")}})
        actions.append(document)
    for document in mock_decisions(timestamp):
        actions.append({"index": {"_index": triage_index, "_id": document.pop("_id")}})
        actions.append(document)
    return actions


def bulk_delete_actions(findings_index: str, triage_index: str) -> List[Dict]:
    actions: List[Dict] = []
    for index in range(1, 9):
        actions.append({"delete": {"_index": findings_index, "_id": f"{DOC_PREFIX}:finding:{index:02d}"}})
    for index in range(1, 9):
        actions.append({"delete": {"_index": triage_index, "_id": f"{DOC_PREFIX}:decision:{index:02d}"}})
    return actions


def parse_args() -> argparse.Namespace:
    today = dt.date.today().strftime("%Y.%m.%d")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["seed", "purge"], help="Seed or remove the mock dataset.")
    parser.add_argument("--scheme", default=DEFAULT_SCHEME)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--index-date",
        default=today,
        help="Index date suffix in YYYY.MM.DD format. Defaults to today.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_url = f"{args.scheme}://{args.host}:{args.port}"
    findings_index, triage_index = build_indices(args.index_date)
    request("GET", base_url)

    if args.action == "seed":
        timestamp = iso_now()
        response = bulk_request(base_url, bulk_index_actions(findings_index, triage_index, timestamp))
        print(
            json.dumps(
                {
                    "action": "seed",
                    "dataset": PIPELINE_SOURCE,
                    "indices": [findings_index, triage_index],
                    "errors": response.get("errors"),
                    "items": len(response.get("items", [])),
                },
                indent=2,
            )
        )
        return 0

    response = bulk_request(base_url, bulk_delete_actions(findings_index, triage_index))
    print(
        json.dumps(
            {
                "action": "purge",
                "dataset": PIPELINE_SOURCE,
                "indices": [findings_index, triage_index],
                "errors": response.get("errors"),
                "items": len(response.get("items", [])),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
