from src.scanners.trivy_scanner import TrivyScanner


def test_trivy_normalizes_misconfig_and_secret_findings(tmp_path):
    target = tmp_path / "docker" / "main.tf"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('resource "aws_s3_bucket" "demo" {}\n', encoding="utf-8")

    scanner = TrivyScanner(provider="aws", scan_ref=str(tmp_path))
    normalized = scanner.normalize_findings(
        [
            {
                "kind": "misconfiguration",
                "target": str(target),
                "payload": {
                    "ID": "AVD-AWS-9999",
                    "Severity": "CRITICAL",
                    "Title": "S3 bucket is public",
                    "Description": "Public bucket detected.",
                    "Resolution": "Restrict public access.",
                    "References": ["https://avd.aquasec.com"],
                    "AVDID": "AVD-AWS-9999",
                    "Type": "Terraform",
                },
            },
            {
                "kind": "secret",
                "target": str(target),
                "payload": {
                    "RuleID": "aws-secret-access-key",
                    "Severity": "HIGH",
                    "Title": "AWS secret exposed",
                    "Match": "AWS_SECRET_ACCESS_KEY=supersecretvalue",
                    "Category": "credential",
                    "StartLine": 4,
                    "EndLine": 4,
                },
            },
        ]
    )

    assert len(normalized) == 2

    misconfig = normalized[0]
    assert misconfig.scanner == "trivy"
    assert misconfig.severity == "CRITICAL"
    assert misconfig.remediation_type == "pr"
    assert misconfig.metadata["file_path"] == str(target)
    assert misconfig.cis_controls == ["https://avd.aquasec.com"]

    secret = normalized[1]
    assert secret.scanner == "trivy"
    assert secret.resource_type == "secret_exposure"
    assert secret.remediation_type == "pipeline_block"
    assert secret.metadata["start_line"] == 4
    assert "AWS_SECRET_ACCESS_KEY" in secret.description
