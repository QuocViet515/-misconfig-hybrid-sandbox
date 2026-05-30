"""
Shared helpers for event-driven post-deployment detection flows.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..models import NormalizedFinding
from ..triage import TriageEngine

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS_ROOT = REPO_ROOT / "artifacts" / "events"


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def save_json(path: str | Path, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def finding_dicts(findings: Iterable[NormalizedFinding]) -> List[Dict[str, Any]]:
    return [finding.model_dump(mode="json") for finding in findings]


def triage_findings(
    findings: Sequence[NormalizedFinding],
    *,
    auto_remediate_threshold: str = "LOW",
) -> List[Dict[str, Any]]:
    engine = TriageEngine({"auto_remediate_threshold": auto_remediate_threshold})
    return [decision.model_dump(mode="json") for decision in engine.triage_batch(list(findings))]


def run_checked(command: List[str], *, cwd: Optional[Path] = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Command failed: {' '.join(command)}")
    return result


def publish_to_siem(
    *,
    findings_path: str | Path,
    decisions_path: str | Path,
    remediation_event_paths: Optional[Sequence[str | Path]] = None,
    metrics_paths: Optional[Sequence[str | Path]] = None,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> None:
    command = [
        sys.executable,
        "-m",
        "src.siem.publisher",
        "--findings",
        str(findings_path),
        "--decisions",
        str(decisions_path),
        "--pipeline-source",
        pipeline_source,
        "--branch",
        branch,
        "--commit-sha",
        commit_sha,
    ]
    for path in remediation_event_paths or []:
        command.extend(["--remediation-events", str(path)])
    for path in metrics_paths or []:
        command.extend(["--metrics", str(path)])
    run_checked(command, cwd=REPO_ROOT)


def build_metrics(
    *,
    findings_path: str | Path,
    decisions_path: str | Path,
    remediation_event_paths: Sequence[str | Path],
    output_path: str | Path,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> Path:
    command = [
        sys.executable,
        "-m",
        "src.remediation.metrics",
        "--findings",
        str(findings_path),
        "--decisions",
        str(decisions_path),
        "--output",
        str(output_path),
        "--pipeline-source",
        pipeline_source,
        "--branch",
        branch,
        "--commit-sha",
        commit_sha,
    ]
    for path in remediation_event_paths:
        command.extend(["--remediation-events", str(path)])
    run_checked(command, cwd=REPO_ROOT)
    return Path(output_path)


def run_runtime_remediation(
    *,
    provider: str,
    findings_path: str | Path,
    decisions_path: str | Path,
    output_dir: str | Path,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
    execute: bool,
    approved_finding_ids: Optional[Sequence[str]] = None,
    region: str = "ap-southeast-1",
    project_prefix: str = "threat-demo",
) -> Dict[str, Path]:
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    if provider == "aws":
        events_path = target_dir / "aws_runtime_events.json"
        findings_after_path = target_dir / "aws_findings_after_runtime.json"
        command = [
            sys.executable,
            "-m",
            "src.remediation.aws_runtime_executor",
            "--findings",
            str(findings_path),
            "--decisions",
            str(decisions_path),
            "--region",
            region,
            "--project-prefix",
            project_prefix,
            "--output-events",
            str(events_path),
            "--output-findings-after",
            str(findings_after_path),
            "--pipeline-source",
            pipeline_source,
            "--branch",
            branch,
            "--commit-sha",
            commit_sha,
        ]
    elif provider == "openstack":
        events_path = target_dir / "openstack_runtime_events.json"
        findings_after_path = target_dir / "openstack_findings_after_runtime.json"
        command = [
            sys.executable,
            "-m",
            "src.remediation.runtime_executor",
            "--findings",
            str(findings_path),
            "--decisions",
            str(decisions_path),
            "--provider",
            "openstack",
            "--output-events",
            str(events_path),
            "--output-findings-after",
            str(findings_after_path),
            "--pipeline-source",
            pipeline_source,
            "--branch",
            branch,
            "--commit-sha",
            commit_sha,
        ]
    else:
        raise ValueError(f"Unsupported provider for runtime remediation: {provider}")

    if execute:
        command.append("--execute")
    for finding_id in approved_finding_ids or []:
        command.extend(["--approve-finding-id", finding_id])

    run_checked(command, cwd=REPO_ROOT)
    return {
        "events_path": events_path,
        "findings_after_path": findings_after_path,
    }

