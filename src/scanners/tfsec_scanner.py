"""
tfsec scanner integration for Terraform findings.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Any, Dict, List
from uuid import uuid4

from . import BaseScanner
from ..models import NormalizedFinding

logger = logging.getLogger(__name__)


class TfsecScanner(BaseScanner):
    """tfsec scanner for Terraform IaC findings."""

    def __init__(self, provider: str, terraform_dir: str):
        super().__init__(provider)
        self.terraform_dir = terraform_dir

    def run(self) -> List[Dict[str, Any]]:
        tfsec_path = shutil.which("tfsec")
        if not tfsec_path:
            logger.warning("tfsec binary not found on PATH. Skipping tfsec scan.")
            return []

        cmd = [
            tfsec_path,
            self.terraform_dir,
            "--format",
            "json",
        ]

        logger.info("Running tfsec command: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)

        if result.returncode not in {0, 1}:
            logger.error("tfsec failed: %s", result.stderr)
            return []

        output = result.stdout.strip()
        if not output:
            logger.warning("tfsec returned no output")
            return []

        report = json.loads(output)
        return self._extract_findings(report)

    def _extract_findings(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        results = report.get("results", [])
        return results if isinstance(results, list) else []

    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        normalized: List[NormalizedFinding] = []
        for raw in raw_findings:
            try:
                location = raw.get("location") or {}
                links = raw.get("links") or []
                severity = raw.get("severity", "MEDIUM")
                finding = NormalizedFinding(
                    finding_id=str(uuid4()),
                    finding_code=str(raw.get("long_id") or raw.get("rule_id") or "TFSEC_UNKNOWN"),
                    scanner="tfsec",
                    provider=self.provider,
                    severity=self.map_severity(severity),
                    title=str(raw.get("rule_description") or raw.get("description") or "tfsec finding"),
                    description=str(raw.get("description") or raw.get("impact") or raw.get("resolution") or ""),
                    resource_type="terraform_resource",
                    resource_id=str(raw.get("resource") or "unknown"),
                    remediation_available=True,
                    remediation_type="pr",
                    cis_controls=[link for link in links if isinstance(link, str)],
                    metadata={
                        "file_path": str(location.get("filename") or ""),
                        "start_line": location.get("start_line"),
                        "end_line": location.get("end_line"),
                        "rule_id": raw.get("rule_id"),
                        "impact": raw.get("impact"),
                        "resolution": raw.get("resolution"),
                    },
                )
                normalized.append(finding)
            except Exception as exc:
                logger.warning("Failed to normalize tfsec finding: %s", exc)
        return normalized
