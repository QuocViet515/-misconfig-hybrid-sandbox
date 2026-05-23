#!/usr/bin/env python3
"""
Provision Dashboard 1 in Kibana using classic saved visualizations.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List


KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601").rstrip("/")
DATA_VIEW_TITLE = "misconfig-findings-*"
DATA_VIEW_NAME = os.getenv("KIBANA_DATA_VIEW_NAME", "misconfig-findings-live")
DASHBOARD_TITLE = "Hybrid Misconfiguration Detection Overview"
KIBANA_VERSION = "8.8.0"
FILTER_QUERY = 'doc_kind.keyword : "finding"'


def api_request(method: str, path: str, payload: Dict[str, Any] | None = None) -> Dict[str, Any]:
    body = None
    headers = {"kbn-xsrf": "true"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        url=f"{KIBANA_URL}{path}",
        data=body,
        headers=headers,
        method=method,
    )
    with urllib.request.urlopen(req) as resp:
        text = resp.read().decode("utf-8")
        return json.loads(text) if text else {}


def stable_uuid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"misconfig-kibana:{name}"))


def find_data_view_id(title: str, preferred_name: str | None = None) -> str:
    search = urllib.parse.quote(title)
    payload = api_request(
        "GET",
        f"/api/saved_objects/_find?type=index-pattern&search_fields=title&search={search}&per_page=100",
    )
    fallback_id = None
    for obj in payload.get("saved_objects", []):
        attributes = obj.get("attributes", {})
        if attributes.get("title") != title:
            continue
        if preferred_name and attributes.get("name") == preferred_name:
            return obj["id"]
        if fallback_id is None:
            fallback_id = obj["id"]
    if fallback_id is not None:
        return fallback_id
    raise SystemExit(f"Data view not found: {title}")


def find_dashboard_id(title: str) -> str | None:
    search = urllib.parse.quote(title)
    payload = api_request(
        "GET",
        f"/api/saved_objects/_find?type=dashboard&search_fields=title&search={search}&per_page=100",
    )
    for obj in payload.get("saved_objects", []):
        if obj.get("attributes", {}).get("title") == title:
            return obj["id"]
    return None


def search_source(index_ref_name: str) -> str:
    return json.dumps(
        {
            "query": {"query": FILTER_QUERY, "language": "kuery"},
            "filter": [],
            "indexRefName": index_ref_name,
        }
    )


def create_visualization(
    *,
    vis_id: str,
    title: str,
    vis_state: Dict[str, Any],
    data_view_id: str,
) -> None:
    payload = {
        "attributes": {
            "title": title,
            "description": "",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": search_source("kibanaSavedObjectMeta.searchSourceJSON.index")
            },
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": data_view_id,
            }
        ],
    }
    api_request("POST", f"/api/saved_objects/visualization/{vis_id}?overwrite=true", payload)


def total_table_vis_state(title: str) -> Dict[str, Any]:
    return {
        "title": title,
        "type": "table",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}
        ],
        "params": {
            "perPage": 1,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showTotal": False,
            "sort": {"columnIndex": None, "direction": None},
            "totalFunc": "sum",
            "percentageCol": "",
        },
    }


def pie_vis_state(title: str, field: str) -> Dict[str, Any]:
    return {
        "title": title,
        "type": "pie",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": field,
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": True,
                    "missingBucket": False,
                },
            },
        ],
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": False, "values": False, "last_level": True, "truncate": 100},
        },
    }


def bar_vis_state(title: str, field: str) -> Dict[str, Any]:
    return {
        "title": title,
        "type": "histogram",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": field,
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "missingBucket": False,
                },
            },
        ],
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False, "style": {"color": "#eee"}},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "truncate": 100},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                    "title": {"text": "Count"},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "histogram",
                    "mode": "stacked",
                    "data": {"label": "Count", "id": "1"},
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": True,
                    "showCircles": True,
                }
            ],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
        },
    }


def create_dashboard(dashboard_id: str, panels: List[Dict[str, Any]]) -> None:
    panel_refs = []
    panels_json = []
    for idx, panel in enumerate(panels):
        ref_name = f"panel_{idx}"
        panel_refs.append({"name": ref_name, "type": "visualization", "id": panel["id"]})
        panels_json.append(
            {
                "version": KIBANA_VERSION,
                "type": "visualization",
                "panelIndex": stable_uuid(f"dashboard-panel-{panel['id']}"),
                "gridData": panel["gridData"],
                "embeddableConfig": {},
                "panelRefName": ref_name,
            }
        )

    payload = {
        "attributes": {
            "title": DASHBOARD_TITLE,
            "description": "Dashboard 1 aligned with the capstone wording in 05_Misconfig_AutoRemediate.md",
            "timeRestore": False,
            "optionsJSON": json.dumps(
                {
                    "useMargins": True,
                    "syncColors": False,
                    "syncCursor": True,
                    "syncTooltips": False,
                    "hidePanelTitles": False,
                }
            ),
            "panelsJSON": json.dumps(panels_json),
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "references": panel_refs,
    }
    api_request("POST", f"/api/saved_objects/dashboard/{dashboard_id}?overwrite=true", payload)


def main() -> int:
    data_view_id = find_data_view_id(DATA_VIEW_TITLE, DATA_VIEW_NAME)

    visualizations = [
        {
            "id": stable_uuid("vis-total-findings"),
            "title": "Total Findings",
            "vis_state": total_table_vis_state("Total Findings"),
            "gridData": {"x": 0, "y": 0, "w": 12, "h": 12, "i": stable_uuid("grid-total")},
        },
        {
            "id": stable_uuid("vis-provider"),
            "title": "Coverage by Cloud Provider",
            "vis_state": pie_vis_state("Coverage by Cloud Provider", "provider.keyword"),
            "gridData": {"x": 12, "y": 0, "w": 18, "h": 12, "i": stable_uuid("grid-provider")},
        },
        {
            "id": stable_uuid("vis-severity"),
            "title": "Misconfiguration Severity Distribution",
            "vis_state": bar_vis_state("Misconfiguration Severity Distribution", "severity.keyword"),
            "gridData": {"x": 30, "y": 0, "w": 18, "h": 12, "i": stable_uuid("grid-severity")},
        },
        {
            "id": stable_uuid("vis-scanner"),
            "title": "Coverage by Scanner",
            "vis_state": bar_vis_state("Coverage by Scanner", "scanner.keyword"),
            "gridData": {"x": 0, "y": 12, "w": 24, "h": 16, "i": stable_uuid("grid-scanner")},
        },
        {
            "id": stable_uuid("vis-resource-type"),
            "title": "Top Affected Resource Types",
            "vis_state": bar_vis_state("Top Affected Resource Types", "resource_type.keyword"),
            "gridData": {"x": 24, "y": 12, "w": 24, "h": 16, "i": stable_uuid("grid-resource-type")},
        },
        {
            "id": stable_uuid("vis-finding-code"),
            "title": "Top Misconfiguration Classes",
            "vis_state": bar_vis_state("Top Misconfiguration Classes", "finding_code.keyword"),
            "gridData": {"x": 0, "y": 28, "w": 48, "h": 16, "i": stable_uuid("grid-finding-code")},
        },
    ]

    for vis in visualizations:
        create_visualization(
            vis_id=vis["id"],
            title=vis["title"],
            vis_state=vis["vis_state"],
            data_view_id=data_view_id,
        )

    dashboard_id = find_dashboard_id(DASHBOARD_TITLE) or stable_uuid("dashboard-1")
    create_dashboard(dashboard_id, visualizations)

    print(f"Provisioned dashboard: {DASHBOARD_TITLE}")
    print(f"Kibana URL: {KIBANA_URL}/app/dashboards#/view/{dashboard_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
