"""
Trivy scanner integration for config and secret findings.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4

from . import BaseScanner
from ..models import NormalizedFinding

logger = logging.getLogger(__name__)


class TrivyScanner(BaseScanner):
    """Trivy scanner for Terraform config and secret findings."""

    def __init__(self, provider: str, scan_ref: str):
        super().__init__(provider)
        self.scan_ref = scan_ref

    def run(self) -> List[Dict[str, Any]]:
        trivy_path = shutil.which("trivy")
        if not trivy_path:
            logger.warning("Trivy binary not found on PATH. Skipping Trivy scan.")
            return []

        cmd = [
            trivy_path,
            "fs",
            "--format",
            "json",
            "--scanners",
            "misconfig,secret",
            "--skip-db-update",
            "--skip-java-db-update",
            "--skip-version-check",
            self.scan_ref,
        ]

        logger.info("Running Trivy command: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)

        if result.returncode not in {0, 1}:
            logger.error("Trivy failed: %s", result.stderr)
            return []

        output = result.stdout.strip()
        if not output:
            logger.warning("Trivy returned no output")
            return []

        report = json.loads(output)
        return self._extract_findings(report)

    def _extract_findings(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for result in report.get("Results", []) or []:
            target = str(result.get("Target") or "")
            for misconfig in result.get("Misconfigurations", []) or []:
                findings.append(
                    {
                        "kind": "misconfiguration",
                        "target": target,
                        "payload": misconfig,
                    }
                )
            for secret in result.get("Secrets", []) or []:
                findings.append(
                    {
                        "kind": "secret",
                        "target": target,
                        "payload": secret,
                    }
                )
        return findings

    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        normalized: List[NormalizedFinding] = []
        for raw in raw_findings:
            try:
                payload = raw.get("payload") or {}
                target = str(raw.get("target") or "")
                kind = str(raw.get("kind") or "unknown")
                file_path = self._resolve_file_path(target)
                if kind == "misconfiguration":
                    finding = NormalizedFinding(
                        finding_id=str(uuid4()),
                        finding_code=str(payload.get("ID") or "TRIVY_MISCONFIG"),
                        scanner="trivy",
                        provider=self.provider,
                        severity=self.map_severity(payload.get("Severity", "MEDIUM")),
                        title=str(payload.get("Title") or payload.get("Message") or "Trivy misconfiguration"),
                        description=str(payload.get("Description") or payload.get("Resolution") or ""),
                        resource_type="terraform_resource",
                        resource_id=target or "unknown",
                        remediation_available=True,
                        remediation_type="pr",
                        cis_controls=[str(item) for item in payload.get("References", []) or []],
                        metadata={
                            "file_path": file_path,
                            "avd_id": payload.get("AVDID"),
                            "resolution": payload.get("Resolution"),
                            "type": payload.get("Type"),
                        },
                    )
                else:
                    finding = NormalizedFinding(
                        finding_id=str(uuid4()),
                        finding_code=str(payload.get("RuleID") or "TRIVY_SECRET"),
                        scanner="trivy",
                        provider=self.provider,
                        severity=self.map_severity(payload.get("Severity", "HIGH")),
                        title=str(payload.get("Title") or payload.get("RuleID") or "Trivy secret finding"),
                        description=str(payload.get("Match") or payload.get("Category") or "Embedded secret detected"),
                        resource_type="secret_exposure",
                        resource_id=target or "unknown",
                        remediation_available=True,
                        remediation_type="pipeline_block",
                        metadata={
                            "file_path": file_path,
                            "category": payload.get("Category"),
                            "start_line": payload.get("StartLine"),
                            "end_line": payload.get("EndLine"),
                            "match": payload.get("Match"),
                        },
                    )
                normalized.append(finding)
            except Exception as exc:
                logger.warning("Failed to normalize Trivy finding: %s", exc)
        return normalized

    @staticmethod
    def _resolve_file_path(target: str) -> str:
        if not target:
            return ""
        path = Path(target)
        return str(path) if path.exists() else target
