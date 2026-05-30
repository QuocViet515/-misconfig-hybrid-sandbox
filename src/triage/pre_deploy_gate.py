"""
Evaluate whether pre-deployment findings should block infrastructure delivery.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from ..siem.publisher import load_decisions, load_findings

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "UNKNOWN")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def recommendation_counts(decisions: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for decision in decisions:
        recommendation = str(decision.get("recommendation") or "unknown")
        counts[recommendation] = counts.get(recommendation, 0) + 1
    return counts


def write_summary(path: str, payload: Dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def findings_at_or_above(findings: List[Dict[str, Any]], threshold: str) -> List[Dict[str, Any]]:
    threshold_rank = SEVERITY_RANK.get(str(threshold or "HIGH").upper(), SEVERITY_RANK["HIGH"])
    return [
        finding
        for finding in findings
        if SEVERITY_RANK.get(str(finding.get("severity") or "UNKNOWN").upper(), -1) >= threshold_rank
    ]


def blocking_pipeline_decisions(decisions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        decision
        for decision in decisions
        if str(decision.get("recommendation") or "").lower() == "pipeline_block"
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the pre-deployment quality gate")
    parser.add_argument("--findings", help="Path to pre-deployment findings JSON")
    parser.add_argument("--decisions", help="Path to pre-deployment triage decisions JSON")
    parser.add_argument("--secret-guard-exit-code", type=int, default=0)
    parser.add_argument("--allow-insecure-override", action="store_true")
    parser.add_argument(
        "--block-severity-at-or-above",
        default="HIGH",
        help="Block deploy when findings at or above this severity are present",
    )
    parser.add_argument(
        "--output",
        default="artifacts/pre_deployment/pre_deployment_gate_summary.json",
        help="Where to write the gate summary JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    findings_payload = load_findings(args.findings) if args.findings and Path(args.findings).exists() else []
    decisions_payload = load_decisions(args.decisions) if args.decisions and Path(args.decisions).exists() else []
    threshold = str(args.block_severity_at_or_above or "HIGH").upper()
    blocking_findings = findings_at_or_above(findings_payload, threshold)
    pipeline_block_decisions = blocking_pipeline_decisions(decisions_payload)

    blocking_reasons: List[str] = []
    if args.secret_guard_exit_code not in (0,):
        blocking_reasons.append(
            f"container_secret_guard_exit_code={args.secret_guard_exit_code}"
        )
    if blocking_findings:
        blocking_reasons.append(
            f"pre_deployment_findings_{threshold.lower()}_or_above={len(blocking_findings)}"
        )
    if pipeline_block_decisions:
        blocking_reasons.append(f"pipeline_block_decisions={len(pipeline_block_decisions)}")

    summary = {
        "allow_insecure_override": args.allow_insecure_override,
        "secret_guard_exit_code": args.secret_guard_exit_code,
        "block_severity_at_or_above": threshold,
        "findings_count": len(findings_payload),
        "decisions_count": len(decisions_payload),
        "severity_counts": severity_counts(findings_payload),
        "recommendation_counts": recommendation_counts(decisions_payload),
        "blocking_findings_count": len(blocking_findings),
        "blocking_findings_ids": [finding.get("finding_id") for finding in blocking_findings],
        "pipeline_block_decisions_count": len(pipeline_block_decisions),
        "pipeline_block_finding_ids": [decision.get("finding_id") for decision in pipeline_block_decisions],
        "blocking_reasons": blocking_reasons,
        "blocked": bool(blocking_reasons) and not args.allow_insecure_override,
    }
    write_summary(args.output, summary)
    print(json.dumps(summary, indent=2))

    if summary["blocked"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
