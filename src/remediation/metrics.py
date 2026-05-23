"""
Build remediation KPI snapshots from findings, decisions, and remediation events.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import NAMESPACE_URL, uuid5

from ..models import MetricSnapshot, RemediationStatus, StatusEnum
from ..siem.publisher import load_decisions, load_findings, load_json_file


OPEN_STATES = {
    StatusEnum.OPEN.value,
    StatusEnum.ACKNOWLEDGED.value,
    StatusEnum.IN_PROGRESS.value,
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def stable_uuid(seed: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"metric:{seed}"))


def load_events(path: str) -> List[Dict[str, Any]]:
    payload = load_json_file(path)
    if isinstance(payload, dict):
        payload = payload.get("events", [])
    if not isinstance(payload, list):
        raise ValueError(f"Unexpected remediation events payload in {path}")
    return [item for item in payload if isinstance(item, dict)]


def save_json(path: str, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def parse_iso(raw: Any) -> Optional[datetime]:
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


def open_finding_count(findings: List[Dict[str, Any]]) -> int:
    count = 0
    for finding in findings:
        status = str(finding.get("status") or StatusEnum.OPEN.value)
        if status in OPEN_STATES:
            count += 1
    return count


def cis_finding_count(findings: List[Dict[str, Any]]) -> int:
    count = 0
    for finding in findings:
        if finding.get("cis_controls"):
            status = str(finding.get("status") or StatusEnum.OPEN.value)
            if status in OPEN_STATES:
                count += 1
    return count


def remediation_success_finding_ids(events: List[Dict[str, Any]]) -> Set[str]:
    return {
        str(event.get("finding_id") or "")
        for event in events
        if str(event.get("action_kind") or "") == "runtime_remediation"
        and str(event.get("status") or "") == RemediationStatus.SUCCESS.value
    }


def apply_runtime_successes(findings: List[Dict[str, Any]], success_ids: Set[str]) -> List[Dict[str, Any]]:
    updated: List[Dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        if str(item.get("finding_id") or "") in success_ids:
            item["status"] = StatusEnum.REMEDIATED.value
            item["remediation_status"] = RemediationStatus.SUCCESS.value
            item["remediated_at"] = item.get("remediated_at") or utc_now_iso()
        updated.append(item)
    return updated


def build_snapshot(
    findings: List[Dict[str, Any]],
    decisions: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    *,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> MetricSnapshot:
    runtime_attempts = [
        event for event in events if str(event.get("action_kind") or "") == "runtime_remediation"
    ]
    runtime_successes = [
        event
        for event in runtime_attempts
        if str(event.get("status") or "") == RemediationStatus.SUCCESS.value
    ]
    runtime_failures = [
        event
        for event in runtime_attempts
        if str(event.get("status") or "") == RemediationStatus.FAILED.value
    ]
    iac_pr_prepared = [
        event
        for event in events
        if str(event.get("action_kind") or "") == "iac_pr_prepare"
        and str(event.get("status") or "") == RemediationStatus.SUCCESS.value
    ]
    success_ids = remediation_success_finding_ids(events)
    findings_after = apply_runtime_successes(findings, success_ids)

    mttr_values: List[float] = []
    finding_lookup = {str(item.get("finding_id") or ""): item for item in findings}
    for event in runtime_successes:
        finding = finding_lookup.get(str(event.get("finding_id") or ""))
        started = parse_iso(finding.get("detected_at") if finding else None)
        completed = parse_iso(event.get("completed_at"))
        if started and completed:
            mttr_values.append((completed - started).total_seconds())

    auto_candidates = sum(1 for decision in decisions if decision.get("recommendation") == "auto_remediate")
    remediation_rate = 0.0
    if runtime_attempts:
        remediation_rate = round(len(runtime_successes) / len(runtime_attempts), 4)

    cis_before = cis_finding_count(findings)
    cis_after = cis_finding_count(findings_after)
    cis_reduction_rate = None
    if cis_before:
        cis_reduction_rate = round((cis_before - cis_after) / cis_before, 4)

    metadata = {
        "iac_pr_prepared_count": len(iac_pr_prepared),
        "runtime_pending_count": sum(
            1
            for event in runtime_attempts
            if str(event.get("status") or "") == RemediationStatus.PENDING.value
        ),
        "runtime_success_finding_ids": sorted(success_ids),
    }

    snapshot = MetricSnapshot(
        metric_id=stable_uuid(f"{pipeline_source}:{branch}:{commit_sha}:{utc_now_iso()}"),
        generated_at=utc_now(),
        pipeline_source=pipeline_source,
        branch=branch,
        commit_sha=commit_sha,
        total_findings=len(findings),
        total_decisions=len(decisions),
        auto_remediate_candidates=auto_candidates,
        remediation_attempts=len(runtime_attempts),
        remediation_successes=len(runtime_successes),
        remediation_failures=len(runtime_failures),
        remediation_rate=remediation_rate,
        mttr_seconds=round(sum(mttr_values) / len(mttr_values), 3) if mttr_values else None,
        open_findings_before=open_finding_count(findings),
        open_findings_after=open_finding_count(findings_after),
        cis_findings_before=cis_before,
        cis_findings_after=cis_after,
        cis_reduction_rate=cis_reduction_rate,
        metadata=metadata,
    )
    return snapshot


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build remediation KPI snapshots")
    parser.add_argument("--findings", required=True)
    parser.add_argument("--decisions", required=True)
    parser.add_argument("--remediation-events", nargs="+", required=True)
    parser.add_argument("--output", default="artifacts/remediation/remediation_metrics.json")
    parser.add_argument("--pipeline-source", default="remediation-metrics")
    parser.add_argument("--branch", default="")
    parser.add_argument("--commit-sha", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings = load_findings(args.findings)
    decisions = load_decisions(args.decisions)
    events: List[Dict[str, Any]] = []
    for path in args.remediation_events:
        events.extend(load_events(path))

    snapshot = build_snapshot(
        findings,
        decisions,
        events,
        pipeline_source=args.pipeline_source,
        branch=args.branch,
        commit_sha=args.commit_sha,
    )
    save_json(args.output, snapshot.model_dump(mode="json"))
    print(json.dumps(snapshot.model_dump(mode="json"), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
