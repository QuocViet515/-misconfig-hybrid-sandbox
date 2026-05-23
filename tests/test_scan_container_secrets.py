from pathlib import Path

from scripts.scan_container_secrets import scan_file


def test_scan_file_detects_embedded_container_secrets(tmp_path):
    dockerfile = tmp_path / "docker" / "Dockerfile"
    dockerfile.parent.mkdir(parents=True, exist_ok=True)
    dockerfile.write_text(
        "\n".join(
            [
                "FROM python:3.11",
                "ENV AWS_SECRET_ACCESS_KEY=abcdefghijklmnopqrstuvwx",
                "ENV DB_PASSWORD=SuperSecret123!",
                "COPY secrets/prod.pem /run/secrets/prod.pem",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    findings = scan_file(Path(dockerfile))
    rule_ids = {finding["rule_id"] for finding in findings}

    assert "AWS_SECRET_ACCESS_KEY" in rule_ids
    assert "PLAINTEXT_PASSWORD" in rule_ids
    assert "PRIVATE_KEY_COPY" in rule_ids
