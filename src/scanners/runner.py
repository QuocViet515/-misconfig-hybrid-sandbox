"""
Scanner orchestration runner
Executes multiple cloud security scanners and aggregates findings
"""
import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from .checkov_scanner import CheckovScanner
from .scoutsuite_scanner import ScoutSuiteScanner
from .cloudsploit_scanner import CloudsploitScanner
from .tfsec_scanner import TfsecScanner
from .trivy_scanner import TrivyScanner
from ..models import NormalizedFinding, ScanResult
from ..config import get_config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ScannerRunner:
    """Orchestrates execution of multiple scanners"""

    def __init__(self, output_dir: str = "./scan_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.config = get_config()
        self.scan_results: List[ScanResult] = []
        self.all_findings: List[NormalizedFinding] = []
        self.scan_start_time = datetime.utcnow()

    def run_scoutsuite(self, provider: str = "aws") -> Optional[ScanResult]:
        """Run ScoutSuite scanner"""
        try:
            logger.info("Starting ScoutSuite scan...")

            profile = os.getenv("AWS_PROFILE", "default")
            region = os.getenv("AWS_REGION", "us-east-1")

            scanner = ScoutSuiteScanner(
                provider=provider,
                profile=profile,
                region=region
            )

            result = scanner.execute()
            logger.info(f"ScoutSuite scan completed: {result.findings_count} findings")

            return result

        except Exception as e:
            logger.error(f"ScoutSuite scan failed: {str(e)}", exc_info=True)
            return None

    def run_checkov(self, terraform_dir: str = "./iac/aws", provider: str = "aws") -> Optional[ScanResult]:
        """Run Checkov IaC scanner"""
        try:
            logger.info("Starting Checkov scan...")

            if not Path(terraform_dir).exists():
                logger.warning(f"Terraform directory not found: {terraform_dir}, skipping Checkov")
                return None

            scanner = CheckovScanner(
                terraform_dir=terraform_dir,
                provider=provider
            )

            result = scanner.execute()
            logger.info(f"Checkov scan completed: {result.findings_count} findings")

            return result

        except Exception as e:
            logger.error(f"Checkov scan failed: {str(e)}", exc_info=True)
            return None

    def run_cloudsploit(self) -> Optional[ScanResult]:
        """Run CloudSploit scanner"""
        try:
            logger.info("Starting CloudSploit scan...")

            profile = os.getenv("AWS_PROFILE", "default")
            region = os.getenv("AWS_REGION", "us-east-1")

            scanner = CloudsploitScanner(
                profile=profile,
                region=region
            )

            result = scanner.execute()
            logger.info(f"CloudSploit scan completed: {result.findings_count} findings")

            return result

        except Exception as e:
            logger.error(f"CloudSploit scan failed: {str(e)}", exc_info=True)
            return None

    def run_tfsec(self, terraform_dir: str = "./iac/aws", provider: str = "aws") -> Optional[ScanResult]:
        """Run tfsec IaC scanner"""
        try:
            logger.info("Starting tfsec scan...")

            if not Path(terraform_dir).exists():
                logger.warning(f"Terraform directory not found: {terraform_dir}, skipping tfsec")
                return None

            scanner = TfsecScanner(
                terraform_dir=terraform_dir,
                provider=provider,
            )

            result = scanner.execute()
            logger.info(f"tfsec scan completed: {result.findings_count} findings")
            return result
        except Exception as e:
            logger.error(f"tfsec scan failed: {str(e)}", exc_info=True)
            return None

    def run_trivy(self, scan_ref: str = "./iac/aws", provider: str = "aws") -> Optional[ScanResult]:
        """Run Trivy config/secret scanner"""
        try:
            logger.info("Starting Trivy scan...")

            if not Path(scan_ref).exists():
                logger.warning(f"Scan reference not found: {scan_ref}, skipping Trivy")
                return None

            scanner = TrivyScanner(
                provider=provider,
                scan_ref=scan_ref,
            )

            result = scanner.execute()
            logger.info(f"Trivy scan completed: {result.findings_count} findings")
            return result
        except Exception as e:
            logger.error(f"Trivy scan failed: {str(e)}", exc_info=True)
            return None

    def aggregate_findings(self) -> None:
        """Aggregate all findings from scanners"""
        for result in self.scan_results:
            if result.status == "success":
                self.all_findings.extend(result.findings)

        logger.info(f"Total findings aggregated: {len(self.all_findings)}")

    def save_results(self) -> None:
        """Save scan results and findings to files"""
        # Save findings
        findings_file = self.output_dir / "findings.json"
        findings_data = [
            finding.model_dump(mode="json") for finding in self.all_findings
        ]

        with open(findings_file, 'w') as f:
            json.dump(findings_data, f, indent=2, default=str)
        logger.info(f"Findings saved to {findings_file}")

        # Save scan results
        results_file = self.output_dir / "scan_results.json"
        results_data = [
            result.model_dump(mode="json") for result in self.scan_results
        ]

        with open(results_file, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        logger.info(f"Scan results saved to {results_file}")

        # Save summary
        summary = self._generate_summary()
        summary_file = self.output_dir / "summary.json"

        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        logger.info(f"Summary saved to {summary_file}")

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate scan summary"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        }

        for finding in self.all_findings:
            severity = finding.severity
            if severity in severity_counts:
                severity_counts[severity] += 1

        scanner_stats = {}
        for result in self.scan_results:
            scanner_stats[result.scanner_name] = {
                'status': result.status,
                'findings_count': result.findings_count,
                'duration_seconds': (
                        result.end_time - result.start_time
                ).total_seconds() if result.end_time and result.start_time else 0,
                'error_message': result.error_message,
            }

        return {
            'scan_timestamp': self.scan_start_time.isoformat(),
            'duration_seconds': (
                    datetime.utcnow() - self.scan_start_time
            ).total_seconds(),
            'total_findings': len(self.all_findings),
            'by_severity': severity_counts,
            'by_scanner': scanner_stats,
        }

    def print_summary(self) -> None:
        """Print scan summary to console"""
        summary = self._generate_summary()

        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Scan Time: {summary['scan_timestamp']}")
        print(f"Duration: {summary['duration_seconds']:.2f} seconds")
        print(f"\nTotal Findings: {summary['total_findings']}")
        print("\nFindings by Severity:")
        for severity, count in summary['by_severity'].items():
            print(f"  {severity}: {count}")

        print("\nScanner Results:")
        for scanner, stats in summary['by_scanner'].items():
            print(f"\n  {scanner}:")
            print(f"    Status: {stats['status']}")
            print(f"    Findings: {stats['findings_count']}")
            print(f"    Duration: {stats['duration_seconds']:.2f}s")
            if stats['error_message']:
                print(f"    Error: {stats['error_message']}")

        print("\n" + "="*60 + "\n")

    def run(
            self,
            enable_scoutsuite: bool = True,
            enable_checkov: bool = True,
            enable_cloudsploit: bool = True,
            enable_tfsec: bool = True,
            enable_trivy: bool = True,
            provider: str = "aws",
            terraform_dir: str = "./iac/aws",
            trivy_scan_ref: str = "./iac/aws",
    ) -> int:
        """
        Execute scanners based on flags

        Args:
            enable_scoutsuite: Run ScoutSuite scanner
            enable_checkov: Run Checkov scanner
            enable_cloudsploit: Run CloudSploit scanner
            terraform_dir: Directory containing Terraform files

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        try:
            logger.info("Starting scanner orchestration...")

            # Execute enabled scanners
            if enable_scoutsuite:
                result = self.run_scoutsuite()
                if result:
                    self.scan_results.append(result)

            if enable_checkov:
                result = self.run_checkov(terraform_dir, provider)
                if result:
                    self.scan_results.append(result)

            if enable_cloudsploit:
                result = self.run_cloudsploit()
                if result:
                    self.scan_results.append(result)

            if enable_tfsec:
                result = self.run_tfsec(terraform_dir, provider)
                if result:
                    self.scan_results.append(result)

            if enable_trivy:
                result = self.run_trivy(trivy_scan_ref, provider)
                if result:
                    self.scan_results.append(result)

            # Aggregate and save results
            self.aggregate_findings()
            self.save_results()
            self.print_summary()

            # Check if any scanner failed critically
            failed_scanners = [
                r.scanner_name for r in self.scan_results
                if r.status == "failed"
            ]

            if failed_scanners:
                logger.warning(f"Some scanners failed: {', '.join(failed_scanners)}")
                return 1 if not self.all_findings else 0

            logger.info("Scanner orchestration completed successfully")
            return 0

        except Exception as e:
            logger.error(f"Scanner orchestration failed: {str(e)}", exc_info=True)
            return 1


def main():
    """Main entry point for scanner runner"""
    parser = argparse.ArgumentParser(
        description="Cloud security scanner orchestrator"
    )

    parser.add_argument(
        "--scoutsuite",
        action="store_true",
        help="Run ScoutSuite scanner"
    )
    parser.add_argument(
        "--checkov",
        action="store_true",
        help="Run Checkov IaC scanner"
    )
    parser.add_argument(
        "--cloudsploit",
        action="store_true",
        help="Run CloudSploit scanner"
    )
    parser.add_argument(
        "--tfsec",
        action="store_true",
        help="Run tfsec scanner"
    )
    parser.add_argument(
        "--trivy",
        action="store_true",
        help="Run Trivy scanner"
    )
    parser.add_argument(
        "--output-dir",
        default="./scan_results",
        help="Output directory for scan results (default: ./scan_results)"
    )
    parser.add_argument(
        "--provider",
        default="aws",
        help="Cloud provider label attached to normalized IaC findings (default: aws)"
    )
    parser.add_argument(
        "--terraform-dir",
        default="./iac/aws",
        help="Terraform directory for Checkov (default: ./iac/aws)"
    )
    parser.add_argument(
        "--trivy-scan-ref",
        default="./iac/aws",
        help="Path for Trivy filesystem scan (default: ./iac/aws)"
    )

    args = parser.parse_args()

    # If no scanners specified, enable all
    enable_all = not (args.scoutsuite or args.checkov or args.cloudsploit or args.tfsec or args.trivy)

    runner = ScannerRunner(output_dir=args.output_dir)
    exit_code = runner.run(
        enable_scoutsuite=args.scoutsuite or enable_all,
        enable_checkov=args.checkov or enable_all,
        enable_cloudsploit=args.cloudsploit or enable_all,
        enable_tfsec=args.tfsec or enable_all,
        enable_trivy=args.trivy or enable_all,
        provider=args.provider,
        terraform_dir=args.terraform_dir,
        trivy_scan_ref=args.trivy_scan_ref,
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
