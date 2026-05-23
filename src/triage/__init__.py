import logging
from typing import List, Dict, Any
from ..models import SeverityLevel, NormalizedFinding, TriageDecision, StatusEnum

logger = logging.getLogger(__name__)

class TriageEngine:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.auto_remediate_threshold = self.config.get('auto_remediate_threshold', 'LOW')
        self.high_risk_resources = self.config.get('high_risk_resources', ['prod', 'production'])

    def triage_finding(self, finding: NormalizedFinding) -> TriageDecision:
        is_auto = self._is_auto_remediate(finding)

        if is_auto:
            recommendation = "auto_remediate"
            confidence = 0.95 if finding.severity in [SeverityLevel.LOW, SeverityLevel.MEDIUM] else 0.7
        elif finding.severity == SeverityLevel.CRITICAL:
            recommendation = "manual_review"
            confidence = 0.99
        elif self._is_false_positive(finding):
            recommendation = "manual_review"
            confidence = 0.6
        else:
            recommendation = "manual_review"
            confidence = 0.8

        reasoning = self._generate_reasoning(finding, recommendation)

        return TriageDecision(
            finding_id=finding.finding_id,
            recommendation=recommendation,
            confidence_score=confidence,
            reasoning=reasoning,
            metadata={
                'severity': finding.severity,
                'resource_type': finding.resource_type,
                'remediation_available': finding.remediation_available,
            }
        )
    
    def triage_batch(self, findings: List[NormalizedFinding]) -> List[TriageDecision]:
        decisions = []
        for finding in findings:
            try:
                decision = self.triage_finding(finding=finding)
                decisions.append(decision)
            except Exception as e:
                logger.error(f"Error triaging finding {finding.finding_id}: {str(e)}")
        return decisions
    
    def _is_auto_remediate(self, finding: NormalizedFinding) -> bool:
        if not finding.remediation_available:
            return False
        
        if self._severity_level(finding.severity) > self._severity_level(self.auto_remediate_threshold):
            return False
        
        environment = str(finding.metadata.get('environment', 'unknown')).lower()
        if any(risk in environment for risk in self.high_risk_resources):
            return False
        
        if finding.status in [StatusEnum.REMEDIATED, StatusEnum.FALSE_POSITIVE]:
            return False
        
        return True
    
    def _is_false_positive(self, finding: NormalizedFinding) -> bool:

        fp_pattern = {
            'scoutsuite': ['cloudtrail_cloudwatch_logging_enabled', 'cloudtrail_log_file_validation'],
            'checkov': ['CK_CUSTOM_', 'CK_AWS_1'],
        }

        scanner = finding.scanner
        code = finding.finding_code.lower()
        
        if scanner in fp_pattern:
            for pattern in fp_pattern[scanner]:
                if pattern.lower() in code:
                    return True
                
        return False

    @staticmethod
    def _severity_level(severity: SeverityLevel) -> int:
        level_map = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
        }
        if isinstance(severity, str):
            severity = SeverityLevel(severity)
        return level_map.get(severity, 0)
    
    @staticmethod
    def _generate_reasoning(finding: NormalizedFinding, recommendation: str) -> str:
        parts = [
            f"Severity: {finding.severity}",
            f"Resource: {finding.resource_type} ({finding.resource_id})",
            f"Scanner: {finding.scanner}",
        ]
        
        if recommendation == "auto_remediate":
            parts.append("Eligible for automatic remediation based on severity and resource type")
        elif recommendation == "manual_review":
            if finding.severity == SeverityLevel.CRITICAL:
                parts.append("Critical finding requires manual review and approval")
            else:
                parts.append("Manual review recommended")
        
        return "; ".join(parts)
    
    def get_summary(self, decisions: List[TriageDecision]) -> Dict[str, Any]:
        auto_remediate_count = sum(1 for d in decisions if d.recommendation == "auto_remediate")
        manual_review_count = sum(1 for d in decisions if d.recommendation == "manual_review")
        ignore_count = sum(1 for d in decisions if d.recommendation == "ignore")
        
        avg_confidence = sum(d.confidence_score for d in decisions) / len(decisions) if decisions else 0
        
        return {
            'total_decisions': len(decisions),
            'auto_remediate': auto_remediate_count,
            'manual_review': manual_review_count,
            'ignore': ignore_count,
            'avg_confidence_score': round(avg_confidence, 3),
        }
