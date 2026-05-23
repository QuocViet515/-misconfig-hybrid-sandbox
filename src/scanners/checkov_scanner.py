import json
import logging
import subprocess
from typing import List, Dict, Any
from uuid import uuid4

from . import BaseScanner
from ..models import NormalizedFinding, SeverityLevel

logger = logging.getLogger(__name__)

class CheckovScanner(BaseScanner):
    def __init__(self, provider, terraform_dir: str):
        super().__init__(provider)
        self.terraform_dir = terraform_dir

    def run(self) -> List[Dict[str, Any]]:
        try:
            cmd = [
                "checkov",
                "-d", self.terraform_dir,
                "--output", "json",
                "--framework", "terraform",
            ]

            logger.info(f"Running Checkov command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            output = result.stdout
            if not output:
                logger.warning("Checkov returned no output")
                return []
            
            report = json.loads(output)
            return self._extract_findings(report)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Checkov JSON output: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Checkov execution error: {str(e)}")
            raise

    def _extract_findings(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from Checkov report"""
        # findings = []
        
        # # Checkov output has check_type key with failed_checks, passed_checks
        # for check_type in report.get('results', {}).get('failed_checks', []):
        #     findings.append(check_type)
        
        # return findings
        failed_checks = report.get("results", {}).get("failed_checks")
        if failed_checks is None:
            failed_checks = report.get("check_type", {}).get("results", {}).get("failed_checks", [])

        return failed_checks or []

    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        normalized = []
        
        for raw in raw_findings:
            try:
                check_id = str(raw.get('check_id') or 'UNKNOWN')
                check_name = str(raw.get('check_name') or 'Unknown check')

                
                description = raw.get("description")
                if not isinstance(description, str) or not description.strip():
                    description = check_name

                resource_id = str(raw.get('resource') or '')
                file_path = str(raw.get('file_path') or '')
                guideline = raw.get('guideline')
                guideline_text = str(guideline) if guideline is not None else ''
                
                finding = NormalizedFinding(
                    finding_id=str(uuid4()),
                    finding_code=check_id,
                    scanner="checkov",
                    provider=self.provider,
                    severity=self.map_severity(raw.get('check_result', {}).get('result', 'FAILED')),
                    title=check_name,
                    description=description,
                    resource_type='terraform_resource',
                    resource_id=resource_id,
                    remediation_available=True,
                    remediation_type="pr",
                     cis_controls=[guideline_text] if guideline_text else [],
                    metadata={
                        'file_path': file_path,
                        'check_id': check_id,
                        'guideline': guideline_text,
                    }
                )
                normalized.append(finding)
            except Exception as e:
                logger.warning(f"Failed to normalize Checkov finding: {str(e)}")
        
        return normalized


