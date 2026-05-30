#!/usr/bin/env python3
"""
Provision Dashboard 4 in Kibana for runtime and IaC remediation outcomes.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List


KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601").rstrip("/")
REMEDIATION_DATA_VIEW_TITLE = "misconfig-remediation-*"
REMEDIATION_DATA_VIEW_NAME = os.getenv("KIBANA_REMEDIATION_DATA_VIEW_NAME", "misconfig-remediation")
DASHBOARD_TITLE = "Runtime Remediation Outcomes"
KIBANA_VERSION = "8.8.0"
FILTER_QUERY = "*"


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


def find_saved_object_id(object_type: str, title: str, preferred_name: str | None = None) -> str | None:
    search = urllib.parse.quote(title)
    payload = api_request(
        "GET",
        f"/api/saved_objects/_find?type={object_type}&search_fields=title&search={search}&per_page=100",
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
    return fallback_id


def ensure_data_view(title: str, name: str) -> str:
    existing_id = find_saved_object_id("index-pattern", title, preferred_name=name)
    if existing_id:
        return existing_id

    payload = {
        "data_view": {
            "title": title,
            "timeFieldName": "@timestamp",
            "name": name,
        }
    }
    response = api_request("POST", "/api/data_views/data_view", payload)
    data_view = response.get("data_view", {})
    data_view_id = data_view.get("id")
    if not data_view_id:
        raise SystemExit(f"Failed to create data view {name} for {title}")
    return data_view_id


def search_source(query: str, index_ref_name: str) -> str:
    return json.dumps(
        {
            "query": {"query": query, "language": "kuery"},
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
    filter_query: str,
) -> None:
    payload = {
        "attributes": {
            "title": title,
            "description": "",
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": search_source(
                    filter_query,
                    "kibanaSavedObjectMeta.searchSourceJSON.index",
                )
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


def donut_vis_state(title: str, field: str) -> Dict[str, Any]:
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
                    "missingBucket": True,
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


def count_bar_vis_state(title: str, field: str, y_axis_title: str = "Count") -> Dict[str, Any]:
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
                    "missingBucket": True,
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
                    "title": {"text": y_axis_title},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "histogram",
                    "mode": "stacked",
                    "data": {"label": y_axis_title, "id": "1"},
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
                "panelIndex": stable_uuid(f"dashboard-4-panel-{panel['id']}"),
                "gridData": panel["gridData"],
                "embeddableConfig": {},
                "panelRefName": ref_name,
            }
        )

    payload = {
        "attributes": {
            "title": DASHBOARD_TITLE,
            "description": "Dashboard 4 focuses on runtime and IaC remediation execution outcomes.",
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
    remediation_data_view_id = ensure_data_view(REMEDIATION_DATA_VIEW_TITLE, REMEDIATION_DATA_VIEW_NAME)

    visualizations = [
        {
            "id": stable_uuid("vis-remediation-total"),
            "title": "Total Remediation Events",
            "vis_state": total_table_vis_state("Total Remediation Events"),
            "gridData": {"x": 0, "y": 0, "w": 10, "h": 10, "i": stable_uuid("grid-remediation-total")},
        },
        {
            "id": stable_uuid("vis-remediation-status"),
            "title": "Remediation Status Distribution",
            "vis_state": donut_vis_state("Remediation Status Distribution", "status.keyword"),
            "gridData": {"x": 10, "y": 0, "w": 18, "h": 10, "i": stable_uuid("grid-remediation-status")},
        },
        {
            "id": stable_uuid("vis-remediation-provider"),
            "title": "Remediation Events by Cloud Provider",
            "vis_state": donut_vis_state("Remediation Events by Cloud Provider", "provider.keyword"),
            "gridData": {"x": 28, "y": 0, "w": 20, "h": 10, "i": stable_uuid("grid-remediation-provider")},
        },
        {
            "id": stable_uuid("vis-remediation-manual-path"),
            "title": "Manual Approval vs Automatic Path",
            "vis_state": donut_vis_state("Manual Approval vs Automatic Path", "manual_approval"),
            "gridData": {"x": 0, "y": 10, "w": 16, "h": 16, "i": stable_uuid("grid-remediation-manual-path")},
        },
        {
            "id": stable_uuid("vis-remediation-recommendation"),
            "title": "Remediation Recommendation Path",
            "vis_state": donut_vis_state("Remediation Recommendation Path", "recommendation.keyword"),
            "gridData": {"x": 16, "y": 10, "w": 16, "h": 16, "i": stable_uuid("grid-remediation-recommendation")},
        },
        {
            "id": stable_uuid("vis-remediation-action-kind"),
            "title": "Remediation Action Kind",
            "vis_state": donut_vis_state("Remediation Action Kind", "action_kind.keyword"),
            "gridData": {"x": 32, "y": 10, "w": 16, "h": 16, "i": stable_uuid("grid-remediation-action-kind")},
        },
        {
            "id": stable_uuid("vis-remediation-status-provider"),
            "title": "Remediation Events by Pipeline Source",
            "vis_state": count_bar_vis_state("Remediation Events by Pipeline Source", "pipeline_source.keyword"),
            "gridData": {"x": 0, "y": 26, "w": 24, "h": 16, "i": stable_uuid("grid-remediation-pipeline-source")},
        },
        {
            "id": stable_uuid("vis-remediation-finding-code"),
            "title": "Top Remediated Finding Codes",
            "vis_state": count_bar_vis_state("Top Remediated Finding Codes", "finding_code.keyword"),
            "gridData": {"x": 24, "y": 26, "w": 24, "h": 16, "i": stable_uuid("grid-remediation-finding-code")},
        },
    ]

    for vis in visualizations:
        create_visualization(
            vis_id=vis["id"],
            title=vis["title"],
            vis_state=vis["vis_state"],
            data_view_id=remediation_data_view_id,
            filter_query=FILTER_QUERY,
        )

    dashboard_id = find_saved_object_id("dashboard", DASHBOARD_TITLE) or stable_uuid("dashboard-4")
    create_dashboard(dashboard_id, visualizations)

    print(f"Provisioned dashboard: {DASHBOARD_TITLE}")
    print(f"Kibana URL: {KIBANA_URL}/app/dashboards#/view/{dashboard_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
