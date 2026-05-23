#!/usr/bin/env python3
"""
Normalize scanner findings into the canonical schema from 05_Misconfig_AutoRemediate.md:
{id, provider, resource_type, resource_id, finding_code, severity, details, region, timestamp, scanner}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


CANONICAL_FIELDS: Tuple[str, ...] = (
    "id",
    "provider",
    "resource_type",
    "resource_id",
    "finding_code",
    "severity",
    "details",
    "region",
    "timestamp",
    "scanner",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_timestamp(raw: Any) -> str:
    if raw is None:
        return utc_now_iso()

    if isinstance(raw, (int, float)):
        epoch = float(raw)
        if epoch > 10_000_000_000:
            epoch /= 1000.0
        try:
            return (
                datetime.fromtimestamp(epoch, tz=timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except (OSError, OverflowError, ValueError):
            return utc_now_iso()

    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return utc_now_iso()

        if text.isdigit():
            return normalize_timestamp(int(text))

        candidate = text.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(candidate)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        except ValueError:
            return utc_now_iso()

    return utc_now_iso()


def compact_details(parts: Sequence[Any]) -> str:
    cleaned: List[str] = []
    seen = set()
    for part in parts:
        if part is None:
            continue
        text = str(part).strip()
        if not text:
            continue
        if text in seen:
            continue
        seen.add(text)
        cleaned.append(text)
    return " | ".join(cleaned)


def normalize_provider(raw: Any) -> str:
    text = str(raw or "").strip().upper()
    if not text:
        return "UNKNOWN"

    provider_map = {
        "AWS": "AWS",
        "AMAZON": "AWS",
        "AZURE": "AZURE",
        "MICROSOFT": "AZURE",
        "GCP": "GCP",
        "GOOGLE": "GCP",
        "OPENSTACK": "OPENSTACK",
        "KUBERNETES": "KUBERNETES",
        "K8S": "KUBERNETES",
    }
    for key, value in provider_map.items():
        if key in text:
            return value
    return "UNKNOWN"


def infer_provider(*values: Any) -> str:
    blob = " ".join(str(v or "").lower() for v in values)
    if any(token in blob for token in ("arn:aws", "aws_", "aws.", "amazon")):
        return "AWS"
    if any(token in blob for token in ("azurerm_", "azure", "/subscriptions/")):
        return "AZURE"
    if any(token in blob for token in ("google_", "gcp", "projects/")):
        return "GCP"
    if "openstack" in blob:
        return "OPENSTACK"
    if any(token in blob for token in ("kubernetes", "k8s")):
        return "KUBERNETES"
    return "UNKNOWN"


def normalize_severity(raw: Any) -> str:
    text = str(raw or "").strip().upper()
    if not text:
        return "UNKNOWN"

    direct = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
        "INFORMATIONAL": "INFO",
        "UNKNOWN": "UNKNOWN",
        "ERROR": "HIGH",
        "FAIL": "HIGH",
        "FAILED": "HIGH",
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "PASS": "INFO",
        "PASSED": "INFO",
        "OK": "INFO",
        "SUCCESS": "INFO",
    }
    if text in direct:
        return direct[text]

    if "CRIT" in text:
        return "CRITICAL"
    if "HIGH" in text:
        return "HIGH"
    if "MED" in text:
        return "MEDIUM"
    if "LOW" in text:
        return "LOW"
    if "INFO" in text:
        return "INFO"
    if "PASS" in text or "OK" in text:
        return "INFO"
    if "FAIL" in text or "ERROR" in text:
        return "HIGH"
    return "UNKNOWN"


def is_pass_status(raw: Any) -> bool:
    text = str(raw or "").strip().upper()
    if not text:
        return False
    return text in {"PASS", "PASSED", "OK", "SUCCESS", "SAFE", "COMPLIANT"}


def infer_resource_type(resource_id: Any) -> str:
    text = str(resource_id or "").strip()
    if not text:
        return "unknown"
    if "." in text:
        return text.split(".", 1)[0]
    if "/" in text:
        return text.split("/", 1)[0]
    return text


def generate_record_id(payload: Dict[str, Any]) -> str:
    raw = "|".join(
        [
            str(payload.get("scanner", "")),
            str(payload.get("provider", "")),
            str(payload.get("resource_type", "")),
            str(payload.get("resource_id", "")),
            str(payload.get("finding_code", "")),
            str(payload.get("severity", "")),
            str(payload.get("details", "")),
            str(payload.get("region", "")),
            str(payload.get("timestamp", "")),
        ]
    )
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    return f"f_{digest}"


def build_record(
    *,
    scanner: str,
    provider: Any = None,
    resource_type: Any = None,
    resource_id: Any = None,
    finding_code: Any = None,
    severity: Any = None,
    details: Any = None,
    region: Any = None,
    timestamp: Any = None,
) -> Dict[str, Any]:
    resource_id_str = str(resource_id or "unknown")
    resource_type_str = str(resource_type or infer_resource_type(resource_id_str) or "unknown")
    provider_norm = normalize_provider(provider) if provider else infer_provider(resource_id_str, finding_code, details)
    severity_norm = normalize_severity(severity)
    details_str = str(details or "").strip()
    timestamp_norm = normalize_timestamp(timestamp)

    record = {
        "provider": provider_norm,
        "resource_type": resource_type_str,
        "resource_id": resource_id_str,
        "finding_code": str(finding_code or "unknown"),
        "severity": severity_norm,
        "details": details_str,
        "region": str(region or "global"),
        "timestamp": timestamp_norm,
        "scanner": scanner,
    }
    record["id"] = generate_record_id(record)

    # Preserve exact canonical field order in output JSON.
    return {field: record[field] for field in CANONICAL_FIELDS}


def detect_scanner(data: Any, file_path: Path) -> str:
    name = file_path.name.lower()
    if "checkov" in name:
        return "checkov"
    if "tfsec" in name:
        return "tfsec"
    if "trivy" in name:
        return "trivy"
    if "cloudsploit" in name:
        return "cloudsploit"
    if "scoutsuite" in name or "scout_suite" in name:
        return "scoutsuite"

    if isinstance(data, dict):
        if "check_type" in data and "results" in data:
            return "checkov"
        if "Results" in data:
            return "trivy"
        if isinstance(data.get("results"), list):
            first = data["results"][0] if data["results"] else {}
            if isinstance(first, dict) and ("rule_id" in first or "long_id" in first):
                return "tfsec"
            if isinstance(first, dict) and any(k in first for k in ("status", "plugin", "message", "service")):
                return "cloudsploit"
        if "services" in data and isinstance(data["services"], dict):
            return "scoutsuite"
    return "generic"


def extract_first(obj: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def parse_checkov(data: Dict[str, Any], include_passed: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    results = data.get("results", {}) if isinstance(data.get("results"), dict) else {}
    sections = ["failed_checks"]
    if include_passed:
        sections.append("passed_checks")

    for section in sections:
        checks = results.get(section, [])
        if not isinstance(checks, list):
            continue

        for check in checks:
            if not isinstance(check, dict):
                continue

            status = extract_first(check, "status") or ("PASS" if section == "passed_checks" else "FAIL")
            if not include_passed and is_pass_status(status):
                continue

            file_path = extract_first(check, "file_path")
            file_line_range = extract_first(check, "file_line_range")
            details = compact_details(
                [
                    extract_first(check, "check_name", "check_name_short"),
                    extract_first(check, "details", "guideline", "description"),
                    f"file={file_path}" if file_path else None,
                    f"lines={file_line_range}" if file_line_range else None,
                ]
            )

            resource = extract_first(check, "resource", "resource_id", "entity", "file_path")
            finding_code = extract_first(check, "check_id", "bc_check_id", "id")
            severity = extract_first(check, "severity", "bc_category", "status")
            provider = infer_provider(resource, finding_code, file_path, data.get("check_type"))
            timestamp = (
                extract_first(data, "created_at", "timestamp")
                or extract_first(data.get("summary", {}), "created_at", "timestamp")
            )

            findings.append(
                build_record(
                    scanner="checkov",
                    provider=provider,
                    resource_type=infer_resource_type(resource),
                    resource_id=resource,
                    finding_code=finding_code,
                    severity=severity,
                    details=details,
                    region=extract_first(check, "region"),
                    timestamp=timestamp,
                )
            )

    return findings


def parse_tfsec(data: Dict[str, Any], include_passed: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    results = data.get("results", [])
    if not isinstance(results, list):
        return findings

    for item in results:
        if not isinstance(item, dict):
            continue

        status = extract_first(item, "status")
        if not include_passed and is_pass_status(status):
            continue

        location = item.get("location", {}) if isinstance(item.get("location"), dict) else {}
        filename = extract_first(location, "filename")
        start_line = extract_first(location, "start_line", "startLine")
        location_str = None
        if filename:
            location_str = f"{filename}:{start_line}" if start_line else filename

        resource = extract_first(item, "resource", "target") or filename
        details = compact_details(
            [
                extract_first(item, "rule_description", "description", "title"),
                extract_first(item, "impact"),
                extract_first(item, "resolution"),
                f"location={location_str}" if location_str else None,
            ]
        )

        rule_id = extract_first(item, "rule_id", "long_id", "ruleId", "id")
        provider = infer_provider(rule_id, resource, filename)
        findings.append(
            build_record(
                scanner="tfsec",
                provider=provider,
                resource_type=infer_resource_type(resource),
                resource_id=resource,
                finding_code=rule_id,
                severity=extract_first(item, "severity", "status"),
                details=details,
                region=extract_first(item, "region"),
                timestamp=extract_first(data, "generated_at", "timestamp", "created_at"),
            )
        )

    return findings


def parse_trivy(data: Dict[str, Any], include_passed: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    blocks = data.get("Results", [])
    if not isinstance(blocks, list):
        return findings

    for block in blocks:
        if not isinstance(block, dict):
            continue
        target = extract_first(block, "Target")
        block_type = extract_first(block, "Type", "Class")

        misconfigs = block.get("Misconfigurations", [])
        if not isinstance(misconfigs, list):
            continue

        for mis in misconfigs:
            if not isinstance(mis, dict):
                continue

            status = extract_first(mis, "Status")
            if not include_passed and is_pass_status(status):
                continue

            cause = mis.get("CauseMetadata", {}) if isinstance(mis.get("CauseMetadata"), dict) else {}
            resource = extract_first(cause, "Resource", "ResourceName")
            if resource is None:
                resource = extract_first(mis, "Resource", "Target", "Query")
            if resource is None:
                resource = target

            finding_code = extract_first(mis, "ID", "AVDID", "Type")
            severity = extract_first(mis, "Severity", "Status")
            details = compact_details(
                [
                    extract_first(mis, "Title"),
                    extract_first(mis, "Description"),
                    extract_first(mis, "Message"),
                    extract_first(mis, "Resolution"),
                    extract_first(mis, "PrimaryURL"),
                    f"target={target}" if target else None,
                    f"type={block_type}" if block_type else None,
                ]
            )
            provider = infer_provider(resource, finding_code, target, block_type)

            findings.append(
                build_record(
                    scanner="trivy",
                    provider=provider,
                    resource_type=infer_resource_type(resource),
                    resource_id=resource,
                    finding_code=finding_code,
                    severity=severity,
                    details=details,
                    region=extract_first(cause, "Region", "region"),
                    timestamp=extract_first(data, "GeneratedAt", "CreatedAt", "timestamp"),
                )
            )

    return findings


def walk_dicts(node: Any, path: Tuple[str, ...] = ()) -> Iterable[Tuple[Dict[str, Any], Tuple[str, ...]]]:
    if isinstance(node, dict):
        yield node, path
        for key, value in node.items():
            yield from walk_dicts(value, path + (str(key),))
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            yield from walk_dicts(value, path + (str(idx),))


def parse_cloudsploit(data: Dict[str, Any], include_passed: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    provider_hint = extract_first(data, "provider", "cloud")

    for item, _path in walk_dicts(data):
        if not isinstance(item, dict):
            continue

        status = extract_first(item, "status", "state")
        has_cloudsploit_shape = any(k in item for k in ("plugin", "message", "service", "category", "key"))
        if not has_cloudsploit_shape:
            continue
        if not include_passed and is_pass_status(status):
            continue

        resource = extract_first(item, "resource", "resource_id", "item", "target", "name", "arn")
        details = compact_details(
            [
                extract_first(item, "title", "message", "description"),
                extract_first(item, "recommendation", "remediation"),
                f"service={extract_first(item, 'service')}" if extract_first(item, "service") else None,
                f"category={extract_first(item, 'category')}" if extract_first(item, "category") else None,
            ]
        )
        finding_code = extract_first(item, "key", "plugin", "rule_id", "id", "title")
        severity = extract_first(item, "severity", "status")
        provider = normalize_provider(provider_hint) if provider_hint else infer_provider(resource, finding_code, details)

        findings.append(
            build_record(
                scanner="cloudsploit",
                provider=provider,
                resource_type=infer_resource_type(resource),
                resource_id=resource,
                finding_code=finding_code,
                severity=severity,
                details=details,
                region=extract_first(item, "region"),
                timestamp=extract_first(item, "timestamp", "time", "created_at"),
            )
        )

    return findings


def parse_scoutsuite(data: Dict[str, Any], include_passed: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    provider_hint = extract_first(data, "provider", "cloudProvider")

    for item, path in walk_dicts(data):
        if not isinstance(item, dict):
            continue

        level = extract_first(item, "level", "severity", "status")
        description = extract_first(item, "description", "title", "message", "rationale")
        check_id = extract_first(item, "id", "check_id", "rule_id", "name")
        items = item.get("items")

        looks_like_scoutsuite_finding = (
            (level is not None or description is not None)
            and (check_id is not None or isinstance(items, list) or "findings" in path)
        )
        if not looks_like_scoutsuite_finding:
            continue

        if not include_passed and is_pass_status(level):
            continue

        timestamp = extract_first(data, "generated_at", "timestamp", "last_run")
        fallback_code = ".".join(path[-4:]) if path else "scoutsuite.finding"
        base_code = check_id or fallback_code
        details = compact_details(
            [
                description,
                extract_first(item, "recommendation", "fix", "remediation"),
            ]
        )

        if isinstance(items, list) and items:
            for element in items:
                resource = None
                if isinstance(element, dict):
                    resource = extract_first(element, "id", "resource_id", "name", "arn", "item")
                else:
                    resource = str(element)

                findings.append(
                    build_record(
                        scanner="scoutsuite",
                        provider=normalize_provider(provider_hint) if provider_hint else infer_provider(resource, base_code, details),
                        resource_type=infer_resource_type(resource),
                        resource_id=resource,
                        finding_code=base_code,
                        severity=level,
                        details=details,
                        region=extract_first(item, "region"),
                        timestamp=timestamp,
                    )
                )
        else:
            resource = extract_first(item, "resource", "resource_id", "item", "target", "name", "arn")
            findings.append(
                build_record(
                    scanner="scoutsuite",
                    provider=normalize_provider(provider_hint) if provider_hint else infer_provider(resource, base_code, details),
                    resource_type=infer_resource_type(resource),
                    resource_id=resource,
                    finding_code=base_code,
                    severity=level,
                    details=details,
                    region=extract_first(item, "region"),
                    timestamp=timestamp,
                )
            )

    return findings


def parse_generic(data: Dict[str, Any], include_passed: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item, path in walk_dicts(data):
        if not isinstance(item, dict):
            continue

        severity = extract_first(item, "severity", "level", "risk", "status")
        code = extract_first(item, "finding_code", "check_id", "rule_id", "id", "key", "name", "title")
        message = extract_first(item, "message", "description", "detail", "details", "title")
        resource = extract_first(item, "resource", "resource_id", "target", "arn", "name", "item")

        signal_count = sum(x is not None for x in (severity, code, message))
        if signal_count < 2:
            continue

        if not include_passed and is_pass_status(severity):
            continue

        fallback_code = ".".join(path[-4:]) if path else "generic.finding"
        details = compact_details(
            [
                message,
                extract_first(item, "recommendation", "remediation"),
            ]
        )
        findings.append(
            build_record(
                scanner="generic",
                provider=infer_provider(resource, code, details),
                resource_type=infer_resource_type(resource),
                resource_id=resource,
                finding_code=code or fallback_code,
                severity=severity,
                details=details,
                region=extract_first(item, "region", "location"),
                timestamp=extract_first(item, "timestamp", "time", "created_at"),
            )
        )
    return findings


def normalize_document(data: Dict[str, Any], scanner: str, include_passed: bool) -> List[Dict[str, Any]]:
    if scanner == "checkov":
        return parse_checkov(data, include_passed)
    if scanner == "tfsec":
        return parse_tfsec(data, include_passed)
    if scanner == "trivy":
        return parse_trivy(data, include_passed)
    if scanner == "cloudsploit":
        return parse_cloudsploit(data, include_passed)
    if scanner == "scoutsuite":
        return parse_scoutsuite(data, include_passed)
    return parse_generic(data, include_passed)


def deduplicate(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    seen = set()
    for row in findings:
        key = (
            row.get("provider", ""),
            row.get("resource_type", ""),
            row.get("resource_id", ""),
            row.get("finding_code", ""),
            row.get("severity", ""),
        )
        # If key is too empty, fall back to the generated id.
        non_empty = sum(1 for part in key if str(part).strip())
        stable_key = key if non_empty >= 3 else ("id", row.get("id"))

        if stable_key in seen:
            continue
        seen.add(stable_key)
        output.append(row)
    return output


def resolve_inputs(raw_inputs: Sequence[str]) -> List[Path]:
    resolved: List[Path] = []
    for item in raw_inputs:
        path = Path(item)
        if path.is_file():
            resolved.append(path)
            continue
        if path.is_dir():
            resolved.extend(sorted(path.rglob("*.json")))
            continue
        # Treat as glob pattern.
        for glob_match in sorted(Path(".").glob(item)):
            if glob_match.is_file():
                resolved.append(glob_match)
    deduped = sorted(set(p.resolve() for p in resolved))
    return deduped


def load_json_file(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError(f"JSON root must be an object for file: {path}")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize scanner reports to canonical finding schema used in "
            "05_Misconfig_AutoRemediate.md."
        )
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        nargs="+",
        help="Input JSON file(s), directory, or glob pattern(s).",
    )
    parser.add_argument(
        "--scanner",
        default="auto",
        choices=("auto", "checkov", "tfsec", "trivy", "cloudsploit", "scoutsuite", "generic"),
        help="Scanner type. Use 'auto' to detect per file.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="-",
        help="Output file path (default: stdout).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    parser.add_argument(
        "--include-passed",
        action="store_true",
        help="Include passed/compliant checks.",
    )
    parser.add_argument(
        "--no-dedupe",
        action="store_true",
        help="Disable de-duplication.",
    )
    parser.add_argument(
        "--wrap",
        action="store_true",
        help="Wrap output in {generated_at, total, findings}.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_files = resolve_inputs(args.input)
    if not input_files:
        print("No input JSON files found.", file=sys.stderr)
        return 2

    all_findings: List[Dict[str, Any]] = []
    file_count = 0
    for path in input_files:
        try:
            payload = load_json_file(path)
        except Exception as exc:  # pylint: disable=broad-except
            print(f"[WARN] Skip {path}: {exc}", file=sys.stderr)
            continue

        scanner = args.scanner if args.scanner != "auto" else detect_scanner(payload, path)
        normalized = normalize_document(payload, scanner, include_passed=args.include_passed)
        all_findings.extend(normalized)
        file_count += 1

    if not args.no_dedupe:
        all_findings = deduplicate(all_findings)

    output_payload: Any
    if args.wrap:
        output_payload = {
            "generated_at": utc_now_iso(),
            "total": len(all_findings),
            "processed_files": file_count,
            "findings": all_findings,
        }
    else:
        output_payload = all_findings

    json_text = json.dumps(output_payload, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.output == "-":
        print(json_text)
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_text + "\n", encoding="utf-8")
        print(f"Wrote {len(all_findings)} findings to {output_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
