import json
import sys
from pathlib import Path

from src.triage import pre_deploy_gate


def write_json(path: Path, payload):
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_pre_deploy_gate_blocks_when_findings_exist(tmp_path: Path, monkeypatch):
    findings_path = tmp_path / "findings.json"
    decisions_path = tmp_path / "decisions.json"
    output_path = tmp_path / "gate.json"

    write_json(
        findings_path,
        [
            {
                "finding_id": "f-1",
                "severity": "HIGH",
                "status": "OPEN",
            }
        ],
    )
    write_json(
        decisions_path,
        {
            "decisions": [
                {
                    "finding_id": "f-1",
                    "recommendation": "manual_review",
                    "confidence_score": 0.8,
                }
            ]
        },
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "pre_deploy_gate.py",
            "--findings",
            str(findings_path),
            "--decisions",
            str(decisions_path),
            "--output",
            str(output_path),
        ],
    )

    assert pre_deploy_gate.main() == 1
    summary = json.loads(output_path.read_text(encoding="utf-8"))
    assert summary["blocked"] is True
    assert summary["findings_count"] == 1


def test_pre_deploy_gate_allows_override(tmp_path: Path, monkeypatch):
    findings_path = tmp_path / "findings.json"
    output_path = tmp_path / "gate.json"

    write_json(findings_path, [{"finding_id": "f-1", "severity": "LOW", "status": "OPEN"}])

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "pre_deploy_gate.py",
            "--findings",
            str(findings_path),
            "--secret-guard-exit-code",
            "2",
            "--allow-insecure-override",
            "--output",
            str(output_path),
        ],
    )

    assert pre_deploy_gate.main() == 0
    summary = json.loads(output_path.read_text(encoding="utf-8"))
    assert summary["blocked"] is False
    assert summary["allow_insecure_override"] is True
