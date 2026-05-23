"""
Publish normalized findings and triage decisions to Elasticsearch.
"""
from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from elasticsearch import Elasticsearch, helpers

from ..config import get_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def normalize_timestamp(raw: Any) -> str:
    if raw is None:
        return utc_now_iso()

    if isinstance(raw, (int, float)):
        value = float(raw)
        if value > 10_000_000_000:
            value /= 1000.0
        return (
            datetime.fromtimestamp(value, tz=timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    text = str(raw).strip()
    if not text:
        return utc_now_iso()

    if text.isdigit():
        return normalize_timestamp(int(text))

    candidate = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        return utc_now_iso()

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_findings(path: str) -> List[Dict[str, Any]]:
    payload = load_json_file(path)
    if isinstance(payload, dict):
        findings = payload.get("findings", [])
    else:
        findings = payload

    if not isinstance(findings, list):
        raise ValueError(f"Unexpected findings payload in {path}")

    return [item for item in findings if isinstance(item, dict)]


def load_decisions(path: str) -> List[Dict[str, Any]]:
    payload = load_json_file(path)
    if isinstance(payload, dict):
        decisions = payload.get("decisions", [])
    else:
        decisions = payload

    if not isinstance(decisions, list):
        raise ValueError(f"Unexpected decisions payload in {path}")

    return [item for item in decisions if isinstance(item, dict)]


def load_events(path: str) -> List[Dict[str, Any]]:
    payload = load_json_file(path)
    if isinstance(payload, dict):
        events = payload.get("events", [])
    else:
        events = payload

    if not isinstance(events, list):
        raise ValueError(f"Unexpected remediation event payload in {path}")

    return [item for item in events if isinstance(item, dict)]


def load_metrics(path: str) -> List[Dict[str, Any]]:
    payload = load_json_file(path)
    if isinstance(payload, list):
        metrics = payload
    elif isinstance(payload, dict):
        metrics = [payload]
    else:
        raise ValueError(f"Unexpected metrics payload in {path}")
    return [item for item in metrics if isinstance(item, dict)]


def enrich_canonical_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding.setdefault("finding_id", finding.get("id"))
    finding.setdefault("title", finding.get("finding_code", "finding"))
    finding.setdefault("description", finding.get("details", ""))
    finding.setdefault("detected_at", finding.get("timestamp"))
    finding.setdefault("last_seen_at", finding.get("timestamp"))
    finding.setdefault("status", "OPEN")
    finding.setdefault("remediation_available", False)
    finding.setdefault("metadata", {})
    finding.setdefault("tags", {})
    return finding


def build_finding_doc(
    finding: Dict[str, Any],
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> Dict[str, Any]:
    finding = dict(finding)
    if "finding_id" not in finding and "id" in finding:
        finding = enrich_canonical_finding(finding)

    detected_at = normalize_timestamp(
        finding.get("detected_at") or finding.get("timestamp") or finding.get("last_seen_at")
    )

    doc = dict(finding)
    doc["@timestamp"] = detected_at
    doc["doc_kind"] = "finding"
    doc["ingested_at"] = utc_now_iso()
    doc["pipeline_source"] = pipeline_source
    doc["git_branch"] = branch
    doc["git_commit"] = commit_sha
    doc["finding_uid"] = finding.get("finding_id") or finding.get("id")
    return doc


def build_decision_doc(
    decision: Dict[str, Any],
    finding_lookup: Dict[str, Dict[str, Any]],
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> Dict[str, Any]:
    decision = dict(decision)
    finding_id = str(decision.get("finding_id") or "")
    linked_finding = finding_lookup.get(finding_id, {})

    doc = dict(decision)
    doc["@timestamp"] = normalize_timestamp(decision.get("created_at"))
    doc["doc_kind"] = "triage_decision"
    doc["ingested_at"] = utc_now_iso()
    doc["pipeline_source"] = pipeline_source
    doc["git_branch"] = branch
    doc["git_commit"] = commit_sha
    doc["scanner"] = linked_finding.get("scanner")
    doc["provider"] = linked_finding.get("provider")
    doc["severity"] = linked_finding.get("severity")
    doc["resource_type"] = linked_finding.get("resource_type")
    doc["resource_id"] = linked_finding.get("resource_id")
    doc["title"] = linked_finding.get("title")
    return doc


def build_remediation_doc(
    event: Dict[str, Any],
    finding_lookup: Dict[str, Dict[str, Any]],
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> Dict[str, Any]:
    event = dict(event)
    finding_id = str(event.get("finding_id") or "")
    linked_finding = finding_lookup.get(finding_id, {})

    doc = dict(event)
    doc["@timestamp"] = normalize_timestamp(event.get("completed_at") or event.get("started_at"))
    doc["doc_kind"] = "remediation_event"
    doc["ingested_at"] = utc_now_iso()
    doc["pipeline_source"] = event.get("pipeline_source") or pipeline_source
    doc["git_branch"] = event.get("branch") or branch
    doc["git_commit"] = event.get("commit_sha") or commit_sha
    doc["scanner"] = linked_finding.get("scanner")
    doc["severity"] = linked_finding.get("severity")
    doc["resource_type"] = linked_finding.get("resource_type")
    doc["title"] = linked_finding.get("title")
    return doc


def build_metric_doc(
    metric: Dict[str, Any],
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> Dict[str, Any]:
    doc = dict(metric)
    doc["@timestamp"] = normalize_timestamp(metric.get("generated_at"))
    doc["doc_kind"] = "metric_snapshot"
    doc["ingested_at"] = utc_now_iso()
    doc["pipeline_source"] = metric.get("pipeline_source") or pipeline_source
    doc["git_branch"] = metric.get("branch") or branch
    doc["git_commit"] = metric.get("commit_sha") or commit_sha
    return doc


def index_name(prefix: str, kind: str, timestamp: str) -> str:
    day = normalize_timestamp(timestamp)[:10].replace("-", ".")
    return f"{prefix}-{kind}-{day}"


def build_actions(
    findings: List[Dict[str, Any]],
    decisions: List[Dict[str, Any]],
    remediation_events: List[Dict[str, Any]],
    metrics: List[Dict[str, Any]],
    prefix: str,
    pipeline_source: str,
    branch: str,
    commit_sha: str,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    actions: List[Dict[str, Any]] = []
    finding_lookup: Dict[str, Dict[str, Any]] = {}

    for finding in findings:
        doc = build_finding_doc(finding, pipeline_source, branch, commit_sha)
        finding_uid = str(doc.get("finding_uid") or "")
        if finding_uid:
            finding_lookup[finding_uid] = doc
        actions.append(
            {
                "_index": index_name(prefix, "findings", doc["@timestamp"]),
                "_id": finding_uid or None,
                "_source": doc,
            }
        )

    for decision in decisions:
        doc = build_decision_doc(decision, finding_lookup, pipeline_source, branch, commit_sha)
        decision_id = f"{doc.get('finding_id', 'unknown')}:{doc.get('@timestamp')}"
        actions.append(
            {
                "_index": index_name(prefix, "triage", doc["@timestamp"]),
                "_id": decision_id,
                "_source": doc,
            }
        )

    for event in remediation_events:
        doc = build_remediation_doc(event, finding_lookup, pipeline_source, branch, commit_sha)
        event_id = str(doc.get("event_id") or f"{doc.get('finding_id', 'unknown')}:{doc.get('@timestamp')}")
        actions.append(
            {
                "_index": index_name(prefix, "remediation", doc["@timestamp"]),
                "_id": event_id,
                "_source": doc,
            }
        )

    for metric in metrics:
        doc = build_metric_doc(metric, pipeline_source, branch, commit_sha)
        metric_id = str(doc.get("metric_id") or f"{doc.get('@timestamp')}:metric")
        actions.append(
            {
                "_index": index_name(prefix, "metrics", doc["@timestamp"]),
                "_id": metric_id,
                "_source": doc,
            }
        )

    return actions, finding_lookup


def create_client(args: argparse.Namespace) -> Elasticsearch:
    config = get_config()
    scheme = args.scheme or config.ELASTICSEARCH_SCHEME
    host = args.host or config.ELASTICSEARCH_HOST
    port = args.port or config.ELASTICSEARCH_PORT
    username = args.username if args.username is not None else config.ELASTICSEARCH_USER
    password = args.password if args.password is not None else config.ELASTICSEARCH_PASSWORD

    client_args: Dict[str, Any] = {
        "hosts": [f"{scheme}://{host}:{port}"],
        "request_timeout": 30,
    }
    if username and password:
        client_args["basic_auth"] = (username, password)
    if args.insecure:
        client_args["verify_certs"] = False

    return Elasticsearch(**client_args)


def publish_actions(client: Elasticsearch, actions: List[Dict[str, Any]]) -> Tuple[int, int]:
    success, failed = helpers.bulk(client, actions, refresh="wait_for", stats_only=True)
    return success, failed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish findings/triage docs to Elasticsearch")
    parser.add_argument("--findings", help="Path to findings JSON file")
    parser.add_argument("--decisions", help="Path to triage decisions JSON file")
    parser.add_argument(
        "--remediation-events",
        action="append",
        help="Path to remediation events JSON file. Repeat for multiple files.",
    )
    parser.add_argument(
        "--metrics",
        action="append",
        help="Path to KPI metric JSON file. Repeat for multiple files.",
    )
    parser.add_argument("--host", help="Elasticsearch host override")
    parser.add_argument("--port", type=int, help="Elasticsearch port override")
    parser.add_argument("--scheme", choices=("http", "https"), help="Elasticsearch scheme override")
    parser.add_argument("--username", help="Elasticsearch username override")
    parser.add_argument("--password", help="Elasticsearch password override")
    parser.add_argument("--index-prefix", help="Index prefix override")
    parser.add_argument("--pipeline-source", default="manual", help="Source tag for ingested docs")
    parser.add_argument("--branch", default="", help="Git branch metadata")
    parser.add_argument("--commit-sha", default="", help="Git commit metadata")
    parser.add_argument("--dry-run", action="store_true", help="Build docs but do not publish")
    parser.add_argument(
        "--preview-output",
        default="triage_results/es_publish_preview.json",
        help="Output path for dry-run preview documents",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.findings and not args.decisions and not args.remediation_events and not args.metrics:
        raise SystemExit("Provide at least one of --findings, --decisions, --remediation-events, or --metrics.")

    config = get_config()
    prefix = args.index_prefix or config.ELASTICSEARCH_INDEX_PREFIX
    findings = load_findings(args.findings) if args.findings else []
    decisions = load_decisions(args.decisions) if args.decisions else []
    remediation_events: List[Dict[str, Any]] = []
    if args.remediation_events:
        for path in args.remediation_events:
            remediation_events.extend(load_events(path))
    metrics: List[Dict[str, Any]] = []
    if args.metrics:
        for path in args.metrics:
            metrics.extend(load_metrics(path))

    actions, _ = build_actions(
        findings=findings,
        decisions=decisions,
        remediation_events=remediation_events,
        metrics=metrics,
        prefix=prefix,
        pipeline_source=args.pipeline_source,
        branch=args.branch,
        commit_sha=args.commit_sha,
    )

    logger.info("Prepared %s documents for Elasticsearch", len(actions))
    if not actions:
        return 0

    if args.dry_run:
        sample_path = Path(args.preview_output)
        sample_path.parent.mkdir(parents=True, exist_ok=True)
        sample_path.write_text(
            json.dumps([action["_source"] for action in actions[:10]], indent=2) + "\n",
            encoding="utf-8",
        )
        logger.info("Dry run only. Preview written to %s", sample_path)
        return 0

    client = create_client(args)
    logger.info("Connecting to Elasticsearch at %s", client.transport.node_pool.get().base_url)
    client.info()
    success, failed = publish_actions(client, actions)
    logger.info("Published %s documents (%s failed)", success, failed)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
