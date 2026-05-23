#!/usr/bin/env python3
"""Export the capstone Kibana dashboards and their saved objects."""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601").rstrip("/")
DASHBOARD_TITLES = [
    "Hybrid Misconfiguration Detection Overview",
    "Triage and Remediation Readiness",
    "Compliance Evidence and Investigation Queue",
]
OUTPUT_DIR = Path("artifacts/kibana")


def api_request(method: str, path: str, payload: Dict[str, Any] | None = None) -> Any:
    body = None
    headers = {"kbn-xsrf": "true"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        url=f"{KIBANA_URL}{path}",
        data=body,
        method=method,
        headers=headers,
    )
    with urllib.request.urlopen(request) as response:
        text = response.read().decode("utf-8")
        if not text:
            return {}
        if path.endswith("/_export"):
            return text
        return json.loads(text)


def find_dashboard(title: str) -> Dict[str, Any]:
    query = urllib.parse.quote(title)
    payload = api_request(
        "GET",
        f"/api/saved_objects/_find?type=dashboard&search_fields=title&search={query}&per_page=100",
    )
    for item in payload.get("saved_objects", []):
        if item.get("attributes", {}).get("title") == title:
            return item
    raise SystemExit(f"Dashboard not found: {title}")


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    dashboards = [find_dashboard(title) for title in DASHBOARD_TITLES]

    export_payload = {
        "objects": [{"type": "dashboard", "id": dashboard["id"]} for dashboard in dashboards],
        "includeReferencesDeep": True,
    }
    ndjson = api_request("POST", "/api/saved_objects/_export", export_payload)

    export_path = OUTPUT_DIR / "misconfig_dashboards.ndjson"
    export_path.write_text(ndjson, encoding="utf-8")

    manifest = {
        "kibana_url": KIBANA_URL,
        "dashboards": [
            {
                "title": dashboard["attributes"]["title"],
                "id": dashboard["id"],
                "url": f"{KIBANA_URL}/app/dashboards#/view/{dashboard['id']}",
                "updated_at": dashboard.get("updated_at"),
            }
            for dashboard in dashboards
        ],
        "export_file": str(export_path),
    }
    manifest_path = OUTPUT_DIR / "dashboard_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
