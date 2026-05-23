"""
CloudSploit scanner integration
"""
import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any
from uuid import uuid4

from . import BaseScanner
from ..models import NormalizedFinding, SeverityLevel

logger = logging.getLogger(__name__)


class CloudsploitScanner(BaseScanner):
    """CloudSploit scanner for AWS findings"""
    
    def __init__(self, profile: str = "default", region: str = "us-east-1"):
        super().__init__("aws", region)
        self.profile = profile
    
    def _get_cloudsploit_command(self) -> str:
        """Find CloudSploit executable path or use npx"""
        cloudsploit_path = shutil.which("cloudsploit")
        if cloudsploit_path:
            return cloudsploit_path
        
        npx_path = shutil.which("npx")
        if npx_path:
            logger.info("Using npx to run CloudSploit")
            return "npx"
        
        logger.warning("CloudSploit command not found. Install with: npm install -g cloudsploit")
        return None
    
    def run(self) -> List[Dict[str, Any]]:
        json_output_file = None
        try:
            cloudsploit_cmd = self._get_cloudsploit_command()
            if not cloudsploit_cmd:
                logger.warning("CloudSploit not available, skipping scan")
                return []

            # Tạo file tạm
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                json_output_file = tmp.name

            # === SỬA CUỐI CÙNG: Dùng space-separated + thêm --cloud aws ===
            if cloudsploit_cmd == "npx":
                cmd = [
                    "npx", "cloudsploit", "scan",
                    "--cloud", "aws",           # ← quan trọng
                    "--console", "none",
                    "--json", json_output_file  # ← space, KHÔNG dùng =
                ]
            else:
                cmd = [
                    cloudsploit_cmd, "scan",
                    "--cloud", "aws",
                    "--console", "none",
                    "--json", json_output_file
                ]

            logger.info(f"Running CloudSploit command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.returncode != 0:
                logger.error(f"CloudSploit failed: {result.stderr}")
                return []

            # Kiểm tra file JSON có được tạo không
            json_path = Path(json_output_file)
            if not json_path.exists() or json_path.stat().st_size == 0:
                logger.error("CloudSploit did not generate JSON output file")
                logger.error(f"Stdout: {result.stdout[-800:]}")   # in phần cuối stdout
                logger.error(f"Stderr: {result.stderr[-500:]}")
                return []

            # Đọc JSON
            try:
                with open(json_output_file, 'r', encoding='utf-8') as f:
                    report = json.load(f)
                logger.info(f"CloudSploit report loaded successfully ({len(report)} plugins)")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in CloudSploit output: {e}")
                with open(json_output_file, 'r', encoding='utf-8') as f:
                    logger.error(f"File preview: {f.read(400)}")
                return []
            except Exception as e:
                logger.error(f"Failed to load CloudSploit JSON file: {e}")
                return []

            return self._extract_findings(report)

        except Exception as e:
            logger.error(f"CloudSploit execution error: {str(e)}")
            return []
        finally:
            # Xóa file tạm
            if json_output_file:
                Path(json_output_file).unlink(missing_ok=True)
    
    def _extract_findings(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings from CloudSploit report"""
        findings = []
        
        for plugin, plugin_data in report.items():
            if isinstance(plugin_data, dict):
                for region, region_data in plugin_data.items():
                    if isinstance(region_data, dict):
                        for result in region_data.get('results', []):
                            findings.append({
                                'plugin': plugin,
                                'region': region,
                                'result': result,
                            })
        
        return findings
    
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """Normalize CloudSploit findings"""
        normalized = []
        
        for raw in raw_findings:
            try:
                result = raw.get('result', {})
                plugin = raw.get('plugin', 'unknown')
                
                if result.get('status') != 'FAIL':
                    continue
                
                finding = NormalizedFinding(
                    finding_id=str(uuid4()),
                    finding_code=f"CS-{plugin.upper()}",
                    scanner="cloudsploit",
                    provider="aws",
                    severity=self.map_severity(result.get('severity', 'medium')),
                    title=f"{plugin}: {result.get('message', 'No message')}",
                    description=result.get('message', ''),
                    resource_type=plugin,
                    resource_id=result.get('resource_id', 'unknown'),
                    region=raw.get('region', self.region),
                    remediation_available=True,
                    remediation_type="cloud_custodian",
                    metadata={
                        'plugin': plugin,
                        'region': raw.get('region'),
                        'status': result.get('status'),
                    }
                )
                normalized.append(finding)
            except Exception as e:
                logger.warning(f"Failed to normalize CloudSploit finding: {str(e)}")
        
        return normalized