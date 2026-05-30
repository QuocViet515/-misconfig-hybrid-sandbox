from src.openstack.findings import parse_security_group_rules


def test_parse_security_group_rules_uses_rule_id_for_remediation_target(tmp_path):
    payload = [
        {
            "ID": "rule-123",
            "Security Group ID": "sg-456",
            "Security Group": "threat-demo-m2-wide-open-sg",
            "Direction": "ingress",
            "IP Range": "0.0.0.0/0",
            "IP Protocol": "tcp",
            "Port Range": "22:22",
        }
    ]
    source = tmp_path / "security_group_rules.json"
    source.write_text(__import__("json").dumps(payload), encoding="utf-8")

    findings = parse_security_group_rules(str(source))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.resource_type == "security_group_rule"
    assert finding.resource_id == "rule-123"
    assert finding.resource_name == "threat-demo-m2-wide-open-sg"
    assert finding.metadata["rule_id"] == "rule-123"
    assert finding.metadata["security_group_id"] == "sg-456"
