package misconfig.iam_wildcard

default review = {
  "review_required": false,
  "risk": "LOW",
  "ticket_priority": "P4",
  "reasons": [],
}

wildcard_reasons contains reason if {
  finding := input.findings[_]
  code := finding.finding_code
  startswith(code, "CKV_AWS_")
  reason := sprintf("%s on %s requires manual IAM review", [code, finding.resource_id])
}

review = {
  "review_required": true,
  "risk": "HIGH",
  "ticket_priority": "P2",
  "reasons": reasons,
} if {
  reasons := [reason | wildcard_reasons contains reason]
  count(reasons) > 0
}
