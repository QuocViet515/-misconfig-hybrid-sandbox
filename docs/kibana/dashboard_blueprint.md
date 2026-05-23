# Dashboard Blueprint

Mục tiêu của blueprint này là đổi dashboard từ kiểu quan sát log chung sang dashboard khớp với wording của capstone trong `05_Misconfig_AutoRemediate.md`.

## Dashboard 1: Hybrid Misconfiguration Detection Overview

Phù hợp với các phần:

- Objectives
- Threat Model & Attack Scenarios
- Logging & SIEM
- Milestone tuần 3-6

Panels:

1. `Total Findings`
   - Type: Metric
   - Data view: `misconfig-findings`
   - Formula: `Count`
   - Filter: `doc_kind : "finding"`

2. `Coverage by Cloud Provider`
   - Type: Donut
   - Slice: `provider.keyword`
   - Filter: `doc_kind : "finding"`

3. `Coverage by Scanner`
   - Type: Bar
   - X axis: `scanner.keyword`
   - Y axis: `Count`
   - Filter: `doc_kind : "finding"`

4. `Misconfiguration Severity Distribution`
   - Type: Bar
   - X axis: `severity.keyword`
   - Y axis: `Count`
   - Filter: `doc_kind : "finding"`

5. `Top Misconfiguration Classes`
   - Type: Bar
   - X axis: `finding_code.keyword`
   - Y axis: `Count`
   - Filter: `doc_kind : "finding"`

## Dashboard 2: Triage and Remediation Readiness

Phù hợp với các phần:

- Detection & Triage Engine
- workflow phê duyệt
- Milestone tuần 7-10

Panels:

1. `Triage Outcomes`
   - Type: Donut
   - Slice: `recommendation.keyword`
   - Data view: `misconfig-triage`
   - Filter: `doc_kind : "triage_decision"`

2. `Average Triage Confidence`
   - Type: Bar
   - X axis: `recommendation.keyword`
   - Y axis: `Average of confidence_score`
   - Data view: `misconfig-triage`
   - Filter: `doc_kind : "triage_decision"`

3. `Remediation Available vs Not Available`
   - Type: Donut
   - Slice: `remediation_available`
   - Data view: `misconfig-findings`
   - Filter: `doc_kind : "finding"`

4. `Remediation Type Distribution`
   - Type: Donut
   - Slice: `remediation_type.keyword`
   - Data view: `misconfig-findings`
   - Filter: `doc_kind : "finding" and remediation_available : true`

5. `Analyst Queue`
   - Type: Table
   - Columns:
     - `resource_id.keyword`
     - `severity.keyword`
     - `provider.keyword`
     - `scanner.keyword`
     - `recommendation.keyword`

## Dashboard 3: Compliance Evidence and Investigation Queue

Phù hợp với các phần:

- Evaluation Metrics
- compliance score (CIS)
- Deliverables

Panels:

1. `Findings With CIS Evidence`
   - Type: Metric
   - Data view: `misconfig-findings`
   - Filter: `doc_kind : "finding" and cis_controls.keyword : *`

2. `CIS Control References`
   - Type: Bar
   - X axis: `cis_controls.keyword`
   - Y axis: `Count`
   - Filter: `doc_kind : "finding" and cis_controls.keyword : *`

3. `Investigation Queue by Resource Type`
   - Type: Bar
   - X axis: `resource_type.keyword`
   - Y axis: `Count`
   - Filter: `doc_kind : "finding" and status.keyword : "OPEN"`

4. `Evidence Table`
   - Type: Table
   - Columns:
     - `finding_code.keyword`
     - `resource_id.keyword`
     - `cis_controls.keyword`
     - `git_branch.keyword`
     - `pipeline_source.keyword`

## Suggested Demo Narrative

Khi demo, đi theo flow này:

1. `Hybrid Misconfiguration Detection Overview`
   - chứng minh pipeline phát hiện được findings từ AWS và OpenStack
2. `Triage and Remediation Readiness`
   - chứng minh findings được phân luồng theo policy
3. `Compliance Evidence and Investigation Queue`
   - chứng minh có bằng chứng phục vụ audit/reporting

## What To State Honestly

Dashboard hiện tại đã phản ánh tốt:

- detection coverage
- hybrid-cloud visibility
- triage outcomes
- compliance evidence
- remediation readiness

Dashboard hiện tại chưa phản ánh đầy đủ:

- MTTR
- remediation success rate
- false remediation rate
- before/after compliance score

Các KPI đó cần thêm event index cho remediation execution và status transitions.
