#!/usr/bin/env python3
"""Merge multiple JSON list/dict-with-list files into one list payload."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, List


def load_items(path: str, collection_key: str | None) -> List[Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, dict) and collection_key:
        payload = payload.get(collection_key, [])
    elif isinstance(payload, dict) and len(payload) == 1:
        payload = next(iter(payload.values()))
    if not isinstance(payload, list):
        raise SystemExit(f"Expected list-like JSON in {path}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--collection-key",
        default="",
        help="If input payloads are dicts, read this list key from each input.",
    )
    args = parser.parse_args()

    merged: List[Any] = []
    collection_key = args.collection_key or None
    for path in args.inputs:
        merged.extend(load_items(path, collection_key))

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output_path), "count": len(merged)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
