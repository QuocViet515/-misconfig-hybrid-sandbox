from src.scanners.tfsec_scanner import TfsecScanner


def test_tfsec_normalizes_core_fields():
    scanner = TfsecScanner(provider="aws", terraform_dir="./iac/terraform")
    normalized = scanner.normalize_findings(
        [
            {
                "long_id": "aws-s3-enable-bucket-encryption",
                "rule_id": "AWS017",
                "rule_description": "S3 bucket encryption should be enabled",
                "description": "Bucket encryption is disabled.",
                "severity": "HIGH",
                "resource": "aws_s3_bucket.demo",
                "links": ["https://docs.example/cis-3.1"],
                "location": {
                    "filename": "iac/terraform/m4_unencrypted_storage.tf",
                    "start_line": 11,
                    "end_line": 18,
                },
                "impact": "Data at rest can be read without encryption.",
                "resolution": "Enable bucket encryption.",
            }
        ]
    )

    assert len(normalized) == 1
    finding = normalized[0]
    assert finding.scanner == "tfsec"
    assert finding.provider == "aws"
    assert finding.severity == "HIGH"
    assert finding.resource_id == "aws_s3_bucket.demo"
    assert finding.remediation_type == "pr"
    assert finding.cis_controls == ["https://docs.example/cis-3.1"]
    assert finding.metadata["file_path"] == "iac/terraform/m4_unencrypted_storage.tf"
    assert finding.metadata["start_line"] == 11
    assert finding.metadata["resolution"] == "Enable bucket encryption."
