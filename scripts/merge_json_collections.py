#!/usr/bin/env python3
"""Merge multiple JSON list/dict-with-list files into one list payload."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


def load_items(path: str, collection_key: str | None) -> List[Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict) and collection_key:
        payload = payload.get(collection_key, [])
    elif isinstance(payload, dict) and len(payload) == 1:
        payload = next(iter(payload.values()))
    if not isinstance(payload, list):
        raise SystemExit(f"Expected list-like JSON in {path}")
    return payload


def normalize_text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def stable_metadata_signature(metadata: Dict[str, Any]) -> str:
    focus_keys = (
        "dedup_key",
        "port_range",
        "remote_ip",
        "protocol",
        "role",
        "project",
        "read_acl",
        "path",
        "file_path",
        "resource_address",
    )
    focused = {key: metadata.get(key) for key in focus_keys if metadata.get(key) not in (None, "", [], {})}
    return json.dumps(focused, sort_keys=True, default=str)


def is_finding_record(item: Any) -> bool:
    return isinstance(item, dict) and any(
        key in item for key in ("finding_id", "finding_code", "provider", "resource_type", "resource_id", "title")
    )


def build_finding_key(item: Dict[str, Any]) -> Tuple[str, ...]:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    semantic_hint = (
        metadata.get("dedup_key")
        or metadata.get("check_id")
        or metadata.get("rule_id")
        or metadata.get("policy_name")
        or item.get("finding_code")
        or item.get("title")
    )
    return (
        normalize_text(item.get("provider")),
        normalize_text(item.get("resource_type")),
        normalize_text(item.get("resource_id")),
        normalize_text(item.get("resource_name")),
        normalize_text(semantic_hint),
        normalize_text(item.get("severity")),
        stable_metadata_signature(metadata),
    )


def deduplicate_findings(items: List[Any]) -> List[Any]:
    deduped: List[Any] = []
    seen: set[Tuple[str, ...]] = set()
    for item in items:
        if not is_finding_record(item):
            deduped.append(item)
            continue
        key = build_finding_key(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--collection-key",
        default="",
        help="If input payloads are dicts, read this list key from each input.",
    )
    parser.add_argument(
        "--dedup-findings",
        action="store_true",
        help="Apply conservative deduplication for normalized finding payloads.",
    )
    args = parser.parse_args()

    merged: List[Any] = []
    collection_key = args.collection_key or None
    for path in args.inputs:
        merged.extend(load_items(path, collection_key))

    if args.dedup_findings:
        merged = deduplicate_findings(merged)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output_path), "count": len(merged)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
