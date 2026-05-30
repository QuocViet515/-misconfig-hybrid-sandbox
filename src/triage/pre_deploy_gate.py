"""
Evaluate whether pre-deployment findings should block infrastructure delivery.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from ..siem.publisher import load_decisions, load_findings


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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate the pre-deployment quality gate")
    parser.add_argument("--findings", help="Path to pre-deployment findings JSON")
    parser.add_argument("--decisions", help="Path to pre-deployment triage decisions JSON")
    parser.add_argument("--secret-guard-exit-code", type=int, default=0)
    parser.add_argument("--allow-insecure-override", action="store_true")
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

    blocking_reasons: List[str] = []
    if args.secret_guard_exit_code not in (0,):
        blocking_reasons.append(
            f"container_secret_guard_exit_code={args.secret_guard_exit_code}"
        )
    if findings_payload:
        blocking_reasons.append(f"pre_deployment_findings={len(findings_payload)}")

    summary = {
        "allow_insecure_override": args.allow_insecure_override,
        "secret_guard_exit_code": args.secret_guard_exit_code,
        "findings_count": len(findings_payload),
        "decisions_count": len(decisions_payload),
        "severity_counts": severity_counts(findings_payload),
        "recommendation_counts": recommendation_counts(decisions_payload),
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
