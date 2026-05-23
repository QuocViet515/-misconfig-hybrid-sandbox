
import json
import logging
import subprocess
import shutil
import sys
from typing import List, Dict, Any
from uuid import uuid4

from . import BaseScanner
from ..models import NormalizedFinding, SeverityLevel

logger = logging.getLogger(__name__)


class ScoutSuiteScanner(BaseScanner):
    """ScoutSuite scanner for multi-cloud findings"""
    
    def __init__(self, provider: str = "aws", profile: str = None, region: str = None):
        super().__init__(provider, region)
        self.profile = profile or "default"
        self.report_dir = f"/tmp/scout-{self.scan_id}"
    
    def _get_scoutsuite_command(self):
        """Find ScoutSuite executable path or fallback to python -m scoutsuite"""
        scoutsuite_path = shutil.which("scout")
        if scoutsuite_path:
            return scoutsuite_path

        logger.info("ScoutSuite binary not found on PATH, falling back to python -m scoutsuite")
        return [sys.executable, "-m", "ScoutSuite"]
    
    def run(self) -> List[Dict[str, Any]]:
        """Execute ScoutSuite scan"""
        try:
            scoutsuite_cmd = self._get_scoutsuite_command()
            
            if isinstance(scoutsuite_cmd, list):
                cmd = scoutsuite_cmd + [self.provider, "--report-dir", self.report_dir]
            else:
                cmd = [scoutsuite_cmd, self.provider, "--report-dir", self.report_dir]
            
            if self.provider == "aws":
                cmd.extend(["--regions", self.region])
                if self.profile and self.profile != "default":
                    cmd.extend(["--profile", self.profile])
            elif self.provider == "azure":
                cmd.append("--cli")
            
            logger.info(f"Running ScoutSuite command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.error(f"ScoutSuite failed: {result.stderr}")
                return []

            import glob
            js_files = glob.glob(f"{self.report_dir}/scoutsuite-results/scoutsuite_results_*.js")

            if not js_files:
                logger.error("No ScoutSuite report file found")
                return []
            
            with open(js_files[0], 'r', encoding='utf-8') as f:
                content = f.read()

            if '=' in content:
                json_str = content.split('=', 1)[1].strip().rstrip('; \n')
            else:
                json_str = content

                
            json_start = json_str.find('{')
            if json_start != -1:
                json_str = json_str[json_start:]
            
            report = json.loads(json_str)
            
            return self._extract_findings(report)
        
        except FileNotFoundError:
            logger.warning("ScoutSuite binary not found. Skipping ScoutSuite scan.")
            return []
        except Exception as e:
            logger.error(f"ScoutSuite execution error: {str(e)}")
            return []
    
    def _extract_findings(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from ScoutSuite report"""
        findings = []
        
        if 'services' not in report:
            return findings

        for service, service_data in report['services'].items():
            if not isinstance(service_data, dict) or 'findings' not in service_data:
                continue
            
            for finding_key, finding_data in service_data['findings'].items():
                items = finding_data.get('items', [])
                if not isinstance(items, list):
                    items = [items] if items else []
                
                for item in items:
                    findings.append({
                        'service': service,
                        'finding_type': finding_key,
                        'issue': {
                            **finding_data,
                            'item': item
                        },
                    })
        
        return findings
    
    def _process_service(self, service: str, service_data: Dict) -> List[Dict]:
        """Process findings for a specific service"""
        findings = []
        
        for finding_type, finding_data in service_data.items():
            if isinstance(finding_data, dict) and 'issues' in finding_data:
                for issue in finding_data['issues']:
                    findings.append({
                        'service': service,
                        'finding_type': finding_type,
                        'issue': issue,
                    })
        
        return findings
    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """Normalize ScoutSuite findings"""
        normalized = []
        
        for raw in raw_findings:
            try:
                finding = NormalizedFinding(
                    finding_id=str(uuid4()),
                    finding_code=f"SCOUT-{raw.get('service', 'unknown').upper()}",
                    scanner="scoutsuite",
                    provider=self.provider,
                    severity=self._get_severity(raw),
                    title=raw.get('issue', {}).get('description', 'Unknown finding'),
                    description=raw.get('issue', {}).get('description', ''),
                    resource_type=raw.get('service', 'unknown'),
                    resource_id=str(raw.get('issue', {}).get('resource_id', 'unknown')),
                    region=self.region,
                    remediation_available=True,
                    remediation_type="cloud_custodian",
                    metadata={
                        'raw_issue': raw.get('issue', {}).get('level', 3),
                    }
                )
                normalized.append(finding)
            except Exception as e:
                logger.warning(f"Failed to normalize ScoutSuite finding: {str(e)}")
        
        return normalized
    
    @staticmethod
    def _get_severity(raw_finding: Dict) -> SeverityLevel:
        """Map ScoutSuite severity to normalized level"""
        issue = raw_finding.get('issue', {})
        issue_level = issue.get('level', 'warning')
        level_map = {
            'danger': SeverityLevel.CRITICAL,
            'warning': SeverityLevel.HIGH,
            'info': SeverityLevel.MEDIUM,
        }
        return level_map.get(issue_level, SeverityLevel.MEDIUM)
