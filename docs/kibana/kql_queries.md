# Kibana KQL Queries

## Findings Scope

All findings:

```text
doc_kind : "finding"
```

Critical or high findings:

```text
doc_kind : "finding" and severity : ("CRITICAL" or "HIGH")
```

Only OpenStack findings:

```text
doc_kind : "finding" and provider : "openstack"
```

Only Terraform/Checkov findings:

```text
doc_kind : "finding" and scanner : "checkov"
```

Auto-remediation candidates:

```text
doc_kind : "finding" and remediation_available : true
```

Findings in current demo branch:

```text
doc_kind : "finding" and git_branch : "feat/normalize"
```

Hybrid-cloud view only:

```text
doc_kind : "finding" and provider : ("aws" or "openstack")
```

## Triage Scope

All triage decisions:

```text
doc_kind : "triage_decision"
```

Auto-remediate decisions:

```text
doc_kind : "triage_decision" and recommendation : "auto_remediate"
```

Manual review decisions:

```text
doc_kind : "triage_decision" and recommendation : "manual_review"
```

## Capstone Dashboard Panels

### 1) Hybrid Coverage Overview

Goal in MD:
show scan coverage across hybrid cloud targets and detection sources.

Lens suggestion:

1. Metric: `Count of records`
   Filter:

```text
doc_kind : "finding"
```

2. Donut: `Top values of provider.keyword`
   Filter:

```text
doc_kind : "finding"
```

3. Bar: `Top values of scanner.keyword`
   Filter:

```text
doc_kind : "finding"
```

### 2) Misconfiguration Severity & Classes

Goal in MD:
visualize the types of cloud misconfigurations being detected.

Lens suggestion:

1. Bar: `Top values of severity.keyword`
2. Bar: `Top values of finding_code.keyword`
3. Heatmap or stacked bar:
   X = `provider.keyword`
   Breakdown = `severity.keyword`
   Y = `Count`

Shared filter:

```text
doc_kind : "finding"
```

### 3) Triage Policy Outcomes

Goal in MD:
show how the triage engine classifies findings into automated vs manual paths.

Lens suggestion:

1. Donut: `Top values of recommendation.keyword`
2. Bar: `Average of confidence_score` split by `recommendation.keyword`
3. Table:
   `finding_id.keyword`, `recommendation.keyword`, `confidence_score`, `resource_type.keyword`

Shared filter:

```text
doc_kind : "triage_decision"
```

### 4) Compliance Evidence (CIS/Policy Links)

Goal in MD:
demonstrate compliance evidence and control mapping.

Lens suggestion:

1. Table:
   `finding_code.keyword`, `cis_controls.keyword`, `resource_id.keyword`
2. Bar:
   `Top values of cis_controls.keyword`

Filter:

```text
doc_kind : "finding" and cis_controls.keyword : *
```

### 5) Remediation Readiness

Goal in MD:
support the transition from detection to remediation and approval workflow.

Lens suggestion:

1. Donut:
   `Top values of remediation_type.keyword`
2. Metric:
   `Count` with filter

```text
doc_kind : "finding" and remediation_available : true
```

3. Table:
   `resource_id.keyword`, `severity.keyword`, `remediation_type.keyword`, `provider.keyword`

Shared filter:

```text
doc_kind : "finding"
```

### 6) Investigation Queue

Goal in MD:
surface the actionable backlog for analysts/approvers.

Lens suggestion:

1. Table:
   `resource_id.keyword`, `title.keyword`, `severity.keyword`, `provider.keyword`, `scanner.keyword`, `status.keyword`
2. Optional filter for current backlog:

```text
doc_kind : "finding" and status.keyword : "OPEN"
```

## Recommended Dashboard Names

Use these names so the dashboard wording matches the capstone report:

1. `Hybrid Misconfiguration Detection Overview`
2. `Triage and Remediation Readiness`
3. `Compliance Evidence and Investigation Queue`

## Suggested Dashboard Layout

For a single demo dashboard:

1. Row 1:
   `Hybrid Coverage Overview` | `Misconfiguration Severity & Classes`
2. Row 2:
   `Triage Policy Outcomes` | `Compliance Evidence (CIS/Policy Links)`
3. Row 3:
   `Remediation Readiness`
4. Row 4:
   `Investigation Queue`

## Gap To Mention In Report

The current data model already supports:

1. detection coverage
2. hybrid-cloud findings
3. triage outcomes
4. remediation readiness
5. compliance evidence via `cis_controls`

The dashboard does not yet show true `MTTR`, `remediation success rate`, or `false-remediation rate`
until remediation execution results are indexed as separate events or status transitions.
