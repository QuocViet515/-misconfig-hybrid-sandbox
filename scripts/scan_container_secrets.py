#!/usr/bin/env python3
"""Fail CI when container-related source files contain embedded secrets."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List


RULES = [
    {
        "id": "AWS_ACCESS_KEY_ID",
        "severity": "CRITICAL",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "message": "AWS access key literal found in source.",
    },
    {
        "id": "AWS_SECRET_ACCESS_KEY",
        "severity": "CRITICAL",
        "pattern": re.compile(r"AWS_SECRET_ACCESS_KEY\s*=\s*[A-Za-z0-9/+=]{20,}"),
        "message": "AWS secret access key found in source.",
    },
    {
        "id": "LIVE_API_KEY",
        "severity": "CRITICAL",
        "pattern": re.compile(r"(sk_live_[A-Za-z0-9]+|SG\.[A-Za-z0-9._-]+)"),
        "message": "Live API credential found in source.",
    },
    {
        "id": "PLAINTEXT_PASSWORD",
        "severity": "HIGH",
        "pattern": re.compile(r"(DB_PASSWORD|password)\s*[:=]\s*[\"']?[A-Za-z0-9!@#$%^&*()_+\-={}\[\]:;,.?/]{8,}"),
        "message": "Plaintext password-like value found in source.",
    },
    {
        "id": "PRIVATE_KEY_COPY",
        "severity": "HIGH",
        "pattern": re.compile(r"COPY\s+secrets/.*(pem|key)", re.IGNORECASE),
        "message": "Private key material copied into container build context.",
    },
]

ALLOWED_SUFFIXES = {".tf", ".dockerfile", ".txt", ".env", ".yaml", ".yml", ".json", ""}
DEFAULT_PATHS = ["iac/terraform/m6_container_secrets.tf", "iac/terraform/docker"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect embedded secrets in container-related sources.")
    parser.add_argument("--paths", nargs="+", default=DEFAULT_PATHS, help="Files or directories to scan")
    parser.add_argument(
        "--output",
        default="artifacts/security/container_secret_report.json",
        help="Where to write the JSON report",
    )
    return parser.parse_args()


def interesting_file(path: Path) -> bool:
    if path.is_dir():
        return False
    if path.name.startswith("."):
        return False
    if "docker" in path.parts:
        return True
    if "container" in path.name.lower():
        return True
    if path.suffix.lower() in ALLOWED_SUFFIXES:
        return True
    return path.name.startswith("Dockerfile")


def iter_files(paths: Iterable[str]) -> Iterable[Path]:
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            if interesting_file(path):
                yield path
            continue
        if not path.exists():
            continue
        for file_path in path.rglob("*"):
            if interesting_file(file_path):
                yield file_path


def scan_file(path: Path) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for line_no, line in enumerate(content.splitlines(), start=1):
        for rule in RULES:
            match = rule["pattern"].search(line)
            if not match:
                continue
            findings.append(
                {
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "message": rule["message"],
                    "file_path": str(path),
                    "line": line_no,
                    "match_excerpt": match.group(0)[:160],
                }
            )
    return findings


def write_report(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    findings: List[Dict[str, str]] = []
    scanned_files = []
    for file_path in sorted(set(iter_files(args.paths))):
        scanned_files.append(str(file_path))
        findings.extend(scan_file(file_path))

    payload = {
        "summary": {
            "scanned_files": len(scanned_files),
            "finding_count": len(findings),
            "blocked": bool(findings),
        },
        "scanned_files": scanned_files,
        "findings": findings,
    }
    write_report(Path(args.output), payload)

    if findings:
        print(f"Detected {len(findings)} container secret findings. See {args.output}", file=sys.stderr)
        return 2

    print(f"No embedded container secrets found. Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
