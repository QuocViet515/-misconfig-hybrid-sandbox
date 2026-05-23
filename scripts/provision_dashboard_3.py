#!/usr/bin/env python3
"""
Provision Dashboard 3 in Kibana using classic saved visualizations.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List


KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601").rstrip("/")
FINDINGS_DATA_VIEW_TITLE = "misconfig-findings-*"
FINDINGS_DATA_VIEW_NAME = os.getenv("KIBANA_FINDINGS_DATA_VIEW_NAME", "misconfig-findings-live")
DASHBOARD_TITLE = "Compliance Evidence and Investigation Queue"
KIBANA_VERSION = "8.8.0"


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


def bar_vis_state(title: str, field: str, y_axis_title: str = "Count") -> Dict[str, Any]:
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


def evidence_table_vis_state(title: str) -> Dict[str, Any]:
    return {
        "title": title,
        "type": "table",
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "bucket",
                "params": {
                    "field": "finding_code.keyword",
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "missingBucket": False,
                },
            },
            {
                "id": "3",
                "enabled": True,
                "type": "terms",
                "schema": "bucket",
                "params": {
                    "field": "resource_id.keyword",
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "missingBucket": False,
                },
            },
            {
                "id": "4",
                "enabled": True,
                "type": "terms",
                "schema": "bucket",
                "params": {
                    "field": "cis_controls.keyword",
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "missingBucket": False,
                },
            },
            {
                "id": "5",
                "enabled": True,
                "type": "terms",
                "schema": "bucket",
                "params": {
                    "field": "git_branch.keyword",
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "missingBucket": False,
                },
            },
            {
                "id": "6",
                "enabled": True,
                "type": "terms",
                "schema": "bucket",
                "params": {
                    "field": "pipeline_source.keyword",
                    "size": 10,
                    "order": "desc",
                    "orderBy": "1",
                    "otherBucket": False,
                    "missingBucket": False,
                },
            },
        ],
        "params": {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showTotal": False,
            "sort": {"columnIndex": None, "direction": None},
            "totalFunc": "sum",
            "percentageCol": "",
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
                "panelIndex": stable_uuid(f"dashboard-3-panel-{panel['id']}"),
                "gridData": panel["gridData"],
                "embeddableConfig": {},
                "panelRefName": ref_name,
            }
        )

    payload = {
        "attributes": {
            "title": DASHBOARD_TITLE,
            "description": "Dashboard 3 aligned with compliance evidence and investigation wording in the capstone.",
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
    findings_data_view_id = ensure_data_view(FINDINGS_DATA_VIEW_TITLE, FINDINGS_DATA_VIEW_NAME)

    evidence_filter = 'doc_kind.keyword : "finding" and cis_controls.keyword : *'
    open_filter = 'doc_kind.keyword : "finding" and status.keyword : "OPEN"'

    visualizations = [
        {
            "id": stable_uuid("vis-cis-evidence-total"),
            "title": "Findings With CIS Evidence",
            "vis_state": total_table_vis_state("Findings With CIS Evidence"),
            "filter_query": evidence_filter,
            "gridData": {"x": 0, "y": 0, "w": 10, "h": 10, "i": stable_uuid("grid-cis-evidence-total")},
        },
        {
            "id": stable_uuid("vis-cis-control-refs"),
            "title": "CIS Control References",
            "vis_state": bar_vis_state("CIS Control References", "cis_controls.keyword"),
            "filter_query": evidence_filter,
            "gridData": {"x": 10, "y": 0, "w": 20, "h": 10, "i": stable_uuid("grid-cis-control-refs")},
        },
        {
            "id": stable_uuid("vis-open-findings-provider"),
            "title": "Open Findings by Provider",
            "vis_state": donut_vis_state("Open Findings by Provider", "provider.keyword"),
            "filter_query": open_filter,
            "gridData": {"x": 30, "y": 0, "w": 18, "h": 10, "i": stable_uuid("grid-open-findings-provider")},
        },
        {
            "id": stable_uuid("vis-investigation-queue-resource-type"),
            "title": "Investigation Queue by Resource Type",
            "vis_state": bar_vis_state("Investigation Queue by Resource Type", "resource_type.keyword"),
            "filter_query": open_filter,
            "gridData": {"x": 0, "y": 10, "w": 24, "h": 16, "i": stable_uuid("grid-investigation-queue-resource-type")},
        },
        {
            "id": stable_uuid("vis-evidence-by-pipeline"),
            "title": "Evidence by Pipeline Source",
            "vis_state": bar_vis_state("Evidence by Pipeline Source", "pipeline_source.keyword"),
            "filter_query": evidence_filter,
            "gridData": {"x": 24, "y": 10, "w": 24, "h": 16, "i": stable_uuid("grid-evidence-by-pipeline")},
        },
        {
            "id": stable_uuid("vis-evidence-table"),
            "title": "Evidence Table",
            "vis_state": evidence_table_vis_state("Evidence Table"),
            "filter_query": evidence_filter,
            "gridData": {"x": 0, "y": 26, "w": 48, "h": 18, "i": stable_uuid("grid-evidence-table")},
        },
    ]

    for vis in visualizations:
        create_visualization(
            vis_id=vis["id"],
            title=vis["title"],
            vis_state=vis["vis_state"],
            data_view_id=findings_data_view_id,
            filter_query=vis["filter_query"],
        )

    dashboard_id = find_saved_object_id("dashboard", DASHBOARD_TITLE) or stable_uuid("dashboard-3")
    create_dashboard(dashboard_id, visualizations)

    print(f"Provisioned dashboard: {DASHBOARD_TITLE}")
    print(f"Kibana URL: {KIBANA_URL}/app/dashboards#/view/{dashboard_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
