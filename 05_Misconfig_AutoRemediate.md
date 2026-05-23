
# Capstone Project Outline  

## Đề tài 5: Tự động phát hiện và khắc phục misconfigurations trên cloud bằng pipeline Ansible + công cụ quét (ScoutSuite, CloudSploit, Checkov)

**Mô tả ngắn:**  
Xây dựng một pipeline tự động để quét phát hiện misconfigurations trên môi trường cloud (OpenStack + AWS/Azure tùy chọn), chuyển kết quả thành alerts/PR/auto-remediation bằng Ansible/Cloud Custodian, đồng thời lưu logs vào SIEM để theo dõi, đánh giá và báo cáo tuân thủ (CIS/CSA). Mục tiêu là giảm thời gian phát hiện và khắc phục, đồng thời cung cấp cơ chế kiểm soát để tránh false-remediation.

---

### 1. Đặt vấn đề (Problem Statement)

- Misconfigurations cloud (public S3, security groups mở, IAM quá quyền, storage unencrypted...) là nguồn lớn gây lộ dữ liệu và các breach.  
- Thực tế: nhiều tổ chức không có quy trình tự động để phát hiện và khắc phục nhanh, dẫn tới MTTR cao.  
- Mục tiêu: một pipeline tự động (scan → triage → remediate/pr → audit) giúp giảm rủi ro, tăng tuân thủ và tối ưu quy trình SecOps/DevSecOps. 

---

### 2. Mục tiêu dự án (Objectives)

- Triển khai pipeline quét định kỳ + on‑demand: ScoutSuite, CloudSploit, Checkov (IaC), tfsec, Trivy.  
- Chuẩn hoá kết quả quét (normalize JSON) và đẩy vào SIEM (Elasticsearch/Logstash/Kibana hoặc Azure Sentinel).  
- Tự động remediations: (A) Auto‑fix via Cloud Custodian / Ansible for runtime misconfi gs; (B) Generate fix PR for IaC (Checkov/Bridgecrew/Repo-AutoPR) for infra-as-code issues.  
- Thiết lập workflow phê duyệt: auto‑remediate only for low‑risk issues, else create ticket/PR & notify approver.  
- Đánh giá: detection coverage, remediation success rate, MTTR, FP rate, compliance score (CIS).
vs
---

### 3. Kiến trúc & Công nghệ sử dụng (Architecture & Tech Stack)

- **Cloud:** OpenStack (lab) + AWS và/or Azure (free tiers).  
- **Scanner/Analyzers:** ScoutSuite (multi-cloud), CloudSploit (checks), Checkov (IaC static analysis), tfsec, Trivy (container/image).  
- **Automation / Remediation:** Ansible (runtime tasks on OpenStack/VM/Cloud APIs), Cloud Custodian (policy-as-code for AWS/Azure), custom Python lambda/Azure Function for glue logic.  
- **CI/CD & Repo integration:** GitHub/GitLab Actions for IaC scan pipelines and automatic PR creation (fix PR). Bridgecrew auto-fix or repo-specific fix scripts.  
- **Logging & SIEM:** Filebeat / Fluentd → Logstash → Elasticsearch → Kibana; or Azure Monitor / Sentinel.  
- **Orchestration:** Workflow engine (Airflow / Argo Workflows) or simple queue (RabbitMQ/Kafka) for scan job orchestration.  
- **Ticketing / ChatOps:** JIRA / ServiceNow integration + Slack/Teams notifications.  
- **Policy & Governance:** Open Policy Agent (OPA) for policy decisions (auto-remediate vs manual).  
- **IaC Tooling:** Terraform, Ansible Playbooks; use tfsec/checkov in pipeline.  

**Kiến trúc (tóm tắt):** Scheduler → Scanner runners (ScoutSuite, CloudSploit, Checkov) → Normalizer → SIEM + Triage Engine (rules/ML) → Action Dispatcher (Cloud Custodian / Ansible / PR creator) → Notification / Ticketing → Audit logs.

---

### 4. Threat Model & Attack Scenarios (Use Cases)

- **M1 – Public S3 bucket**: dữ liệu nhạy cảm bị public do ACL lỗi hoặc bucket policy.  
- **M2 – Security group wide open (0.0.0.0/0)**: SSH/RDP exposed.  
- **M3 – IAM wildcard policy**: user/role với `Action: "*"` dẫn tới privilege escalation.  
- **M4 – Unencrypted storage**: snapshot/volume/object không có encryption-at-rest.  
- **M5 – IaC drift**: môi trường runtime bị chỉnh sửa thủ công khác với IaC => misconfig.  
- **M6 – Container image with secrets**: secret keys embedded in images pushed to registry.  

Mục tiêu: pipeline phát hiện tự động các tình huống trên & khắc phục theo policy.

---

### 5. Dữ liệu & Tiền xử lý (Data Sources & Preprocessing)

**Nguồn dữ liệu:**  

- Output JSON từ ScoutSuite, CloudSploit, Checkov, tfsec, Trivy.  
- Cloud provider APIs response (DescribeBuckets, SecurityGroups, IAM policies), CloudTrail / OpenStack logs.  
- Git commit history & PR metadata (IaC repos).

**Tiền xử lý:**  

1. Convert outputs to canonical JSON schema: `{id, provider, resource_type, resource_id, finding_code, severity, details, region, timestamp, scanner}`.  
2. Deduplication (same finding from multiple scanners).  
3. Severity normalization (map vendor severities → unified severity: CRITICAL/HIGH/MEDIUM/LOW).  
4. Enrichment: link to CIS controls, add asset owner from CMDB, add last_modified_by, IaC file path if available.  
5. Persist to Elastic index or PostgreSQL for triage & history.

---

### 6. Gán nhãn & Triage (Labeling & Prioritization)

- **Static rules:** map scanner result → priority using severity + asset sensitivity (sensitive bucket vs public).  
- **Contextual enrichment:** asset owner, environment (prod/staging/dev), exposure score → determine auto-remediate eligibility.  
- **Human-in-the-loop:** high/critical findings create JIRA ticket and notify security owner; low/medium proceed to auto-remediation pipeline after cooldown.  
- **Weak supervision for ML triage (optional):** use historic triage outcomes to train model to predict remediation path (auto vs manual).

---

### 7. Remediation Strategies (Policy for action)

- **Auto‑Remediate (low-risk):** run Cloud Custodian policy or Ansible playbook to fix setting (e.g., set S3 block public access, remove 0.0.0.0/0 rule).  
- **Generate Fix PR (IaC issues):** create branch, update IaC file (terraform block), push fix branch & open PR for review (use repo token and Checkov/Bridgecrew remediation suggestions).  
- **Quarantine & Contain:** if remediation fails or risk is high, isolate asset (move to quarantine subnet, disable user keys).  
- **Notification & Audit:** log action, send notification, attach remediation diff to ticket.  
- **Rollback plan:** store previous configuration snapshot to revert if remediation breaks production.

**Examples (snippets):**  

_Cloud Custodian policy (AWS S3 block public access):_

```yaml
policies:
  - name: s3-block-public
    resource: aws.s3
    filters:
      - type: value
        key: PublicAccessBlockConfiguration.BlockPublicAcls
        value: false
    actions:
      - type: set-public-access-block
        BlockPublicAcls: true
        BlockPublicPolicy: true
```

_Ansible task (remove wide-open security group ingress):_

```yaml
- name: Remove 0.0.0.0/0 SSH ingress
  community.aws.ec2_group:
    name: "{{ sg_name }}"
    region: "{{ aws_region }}"
    rules:
      - proto: tcp
        from_port: 22
        to_port: 22
        cidr_ip: 0.0.0.0/0
    state: absent
```

_Checkov auto‑fix approach:_ Use Checkov to identify Terraform issue; generate PR with corrected resource block (e.g., add `bucket_policy` or `acl = "private"`).

---

### 8. Detection & Triage Engine (Rules / ML)

- **Rule engine:** Sigma-like rules or OPA policies to mark auto-remediateable vs manual.  
- **ML triage (optional):** model that predicts if finding will be auto-fixed or triaged based on historical decisions — features: scanner, severity, asset_owner_response_time, environment, remediation_history.  
- **Feedback loop:** after remediation success/failure, log result and retrain triage model periodically.

---

### 9. Testing & Validation (Test Plan)

**Test cases:**  

- TC1: Public S3 found by ScoutSuite → auto-remediate via Cloud Custodian; verify bucket no longer public.  
- TC2: Security group with 0.0.0.0/0 for SSH → Ansible removes rule; verify connectivity and alert on change.  
- TC3: IaC terraform with insecure storage policy → Checkov PR generation; merge PR via CI → deploy change; verify drift resolved.  
- TC4: False positive handling: create scenario where scanner reports but owner flags safe → ensure pipeline does not auto-remediate afterward.  
- TC5: Performance test: scale scans for 1000 assets → measure processing time & queue length.  

**Tools:** pytest, local test clouds, mock responses, terraform plan/apply in sandbox, unit tests for normalizer & triage logic.

---

### 10. Deployment & Integration (Ops)

- Deploy scanner runners as containers (Docker) or serverless functions scheduled via cron / Airflow.  
- Use message queue (RabbitMQ/Kafka) to decouple scanning from remediation.  
- Gate auto-remediation behind feature flags / maintenance windows.  
- Integrate with GitOps: IaC repos scanned on PRs & merges.  
- Provide dashboards in Kibana/PowerBI for security owners with filters (by owner, severity, status).

---

### 11. Evaluation Metrics (KPIs)

- **Detection coverage:** % of known misconfig checks automated by scanners.  
- **Remediation rate:** % of findings successfully remediated automatically.  
- **MTTR (Mean Time To Remediate):** time from detection → remediation completion.  
- **False positive rate / false remediation rate:** % of auto-remediations that were reverted or caused issues.  
- **Compliance score:** percentage of CIS benchmarks satisfied before vs after pipeline.  
- **Operational cost:** cloud API calls, runtime overhead.

---

### 12. Rubric đánh giá (Suggested Grading Rubric)

- **Scanner integration & normalization (20%)**: ScoutSuite/CloudSploit/Checkov outputs ingested & normalized.  
- **Triage engine & policies (20%)**: rules/OPA + triage logic implemented.  
- **Automated remediation (25%)**: Cloud Custodian / Ansible remediations working and safe.  
- **IaC fix PR flow (15%)**: auto PR creation for IaC issues, tests run in CI.  
- **Testing, evaluation & reporting (20%)**: test cases, metrics, dashboards, report.

---

### 13. Milestones & Timeline (14 tuần đề xuất)

- Tuần 1–2: Nghiên cứu & design architecture; chọn cloud targets & scanners.  
- Tuần 3–4: Deploy scanner runners; run initial scans; collect outputs.  
- Tuần 5–6: Build normalizer & store findings in Elastic/Postgres.  
- Tuần 7–8: Implement triage rules + OPA policy engine; map to CIS controls.  
- Tuần 9–10: Implement remediation actions (Cloud Custodian policies & Ansible playbooks).  
- Tuần 11: Implement IaC auto‑PR flow & CI integration.  
- Tuần 12: Integration tests & pilot run on sample assets.  
- Tuần 13: Collect metrics, refine FP handling.  
- Tuần 14: Final report, demo, slides.

---

### 14. Deliverables (nộp cuối)

- Git repo: scanner runners, normalizer, triage engine, remediation playbooks, CI configs.  
- SIEM index configs & Kibana dashboards (screenshots + export).  
- Sample datasets & sanitized logs + scripts to re-run scans.  
- Demo video (5–10 phút), Technical report (15–25 trang), Slides (10–15 slides).

---

### 15. Ethical & Safety Considerations

- Không quét hoặc thay đổi tài nguyên bên ngoài lab or customer scope without explicit permission.  
- Auto-remediation must have safe guards (canary, maintenance window, approval for high-risk resources).  
- Avoid storing secrets in logs; sanitize outputs.  
- Provide rollback paths and test remediation on non-prod first.

---

### 16. Extensions & Advanced Ideas (Optional)

- Implement automated canary remediation: apply fix to staging subset, monitor impact, then roll out globally.  
- Build a multi-scanner consensus engine: only remediate when >=N scanners agree.  
- Integrate vulnerability management: tie misconfig findings to CVEs and prioritize accordingly.  
- Use ML for root-cause analysis: cluster recurring misconfig classes and propose IaC refactor suggestions.  
- Provide compliance reporting automation (CIS/ISO/PCI) with evidence for auditors.

---

### 17. Example Commands & Snippets (Appendix)

**Run ScoutSuite (AWS) example:**  

```bash
scoutsuite --report-dir ./reports/aws --account aws_account_id --profile myprofile
```

**Run CloudSploit (Docker):**  

```bash
docker run -it -v $(pwd)/cs-reports:/reports cloudsploit/scanner --config config.yml --output /reports
```

**Checkov in CI (pre-commit):**  

```bash
checkov -d ./terraform --output json > checkov_report.json
```

**Simple Ansible remediation run:**  

```bash
ansible-playbook -i inventory.yml remediate_sg.yml --extra-vars "sg_name=my-sg region=ap-southeast-1"
```

---
