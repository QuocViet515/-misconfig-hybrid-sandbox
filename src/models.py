from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
class SeverityLevel(str, Enum):
    """Severity levels for findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class StatusEnum(str, Enum):
    """Status of a finding"""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    WONT_FIX = "WONT_FIX"

class RemediationStatus(str, Enum):
    """Status of remediation"""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"

class NormalizedFinding(BaseModel):
    """Normalized finding schema"""
    
    # Identifiers
    finding_id: str = Field(..., description="Unique finding identifier")
    finding_code: str = Field(..., description="Scanner-specific finding code")
    
    # Core details
    scanner: str = Field(..., description="Scanner name (scoutsuite, cloudsploit, checkov)")
    provider: str = Field(..., description="Cloud provider (aws, azure, gcp, openstack)")
    severity: SeverityLevel = Field(..., description="Finding severity")
    title: str = Field(..., description="Finding title/name")
    description: str = Field(..., description="Detailed description")
    
    # Resource details
    resource_type: str = Field(..., description="Type of resource (s3, iam, sg, etc)")
    resource_id: str = Field(..., description="Unique resource identifier")
    resource_name: Optional[str] = Field(None, description="Human-readable resource name")
    region: Optional[str] = Field(None, description="AWS region or Azure region")
    
    # Classification
    cis_controls: List[str] = Field(default_factory=list, description="Mapped CIS controls")
    risk_category: Optional[str] = Field(None, description="Risk category")
    
    # Remediation
    remediation_available: bool = Field(False, description="Whether automated remediation is available")
    remediation_type: Optional[str] = Field(None, description="Type of remediation (auto_fix, pr, manual)")
    
    # Timeline
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen_at: datetime = Field(default_factory=datetime.utcnow)
    remediated_at: Optional[datetime] = Field(None)
    
    # Status
    status: StatusEnum = Field(default=StatusEnum.OPEN)
    remediation_status: Optional[RemediationStatus] = Field(None)
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True

class ScanResult(BaseModel):
    """Result of a scanner execution"""
    
    scan_id: str = Field(..., description="Unique scan identifier")
    scanner_name: str = Field(..., description="Name of the scanner")
    provider: str = Field(..., description="Cloud provider")
    start_time: datetime = Field(..., description="Scan start time")
    end_time: datetime = Field(..., description="Scan end time")
    status: str = Field(..., description="Scan status (success or failed)")
    findings_count: int = Field(..., description="Number of findings")
    findings: List[NormalizedFinding] = Field(default_factory=list, description="List of findings")
    error_message: Optional[str] = Field(None, description="Error message if scan failed")
    raw_output: Optional[List[Dict[str, Any]]] = Field(None, description="Raw scanner output")
    
    class Config:
        use_enum_values = True

class TriageDecision(BaseModel):
    """Triage decision for a finding"""
    
    finding_id: str
    recommendation: str  # 'auto_remediate', 'manual_review', 'ignore'
    confidence_score: float  # 0.0 to 1.0
    reasoning: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RemediationEvent(BaseModel):
    """Audit record for a remediation attempt or IaC PR preparation."""

    event_id: str
    finding_id: str
    finding_code: str
    provider: str
    resource_id: str
    action_kind: str  # runtime_remediation, iac_pr_prepare
    recommendation: str
    status: RemediationStatus
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    manual_approval: bool = False
    dry_run: bool = False
    pipeline_source: str = "manual"
    branch: str = ""
    commit_sha: str = ""
    command: Optional[List[str]] = None
    patch_path: Optional[str] = None
    pr_artifact_dir: Optional[str] = None
    notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class MetricSnapshot(BaseModel):
    """Point-in-time KPI snapshot for dashboards and reports."""

    metric_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    pipeline_source: str = "manual"
    branch: str = ""
    commit_sha: str = ""
    total_findings: int = 0
    total_decisions: int = 0
    auto_remediate_candidates: int = 0
    remediation_attempts: int = 0
    remediation_successes: int = 0
    remediation_failures: int = 0
    remediation_rate: float = 0.0
    mttr_seconds: Optional[float] = None
    open_findings_before: int = 0
    open_findings_after: int = 0
    cis_findings_before: int = 0
    cis_findings_after: int = 0
    cis_reduction_rate: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
