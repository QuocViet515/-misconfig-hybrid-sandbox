from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Dict, Any
from uuid import uuid4
import logging

from ..models import NormalizedFinding, ScanResult, SeverityLevel

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    def __init__(self, provider: str, region: str = None):
        self.provider = provider
        self.region = region or "us-east-1"
        self.scan_id = str(uuid4())
        self.start_time = None
        self.end_time = None
        
    @abstractmethod
    def run(self) -> List[Dict[str, Any]]:
        """Execute the runner and return the raw findings"""
        pass

    @abstractmethod
    def normalize_findings(self, raw_findings: List[Dict[str, Any]]) -> List[NormalizedFinding]:
        """Normalize findings to the standard format"""
        pass

    def execute(self) -> ScanResult:
        self.start_time = datetime.utcnow()
        try:
            logger.info(f"Starting {self.__class__.__name__} scan")
            raw_findings = self.run()
            normalized = self.normalize_findings(raw_findings)
            status = "success"
            error_message = None
        except Exception as e:
            logger.error(f"Scanner {self.__class__.__name__} failed: {str(e)}", exc_info=True)
            normalized = []
            status = "failed"
            error_message = str(e)
            raw_findings = []
        
        self.end_time = datetime.utcnow()
        
        return ScanResult(
            scan_id=self.scan_id,
            scanner_name=self.__class__.__name__,
            provider=self.provider,
            start_time=self.start_time,
            end_time=self.end_time,
            status=status,
            findings_count=len(normalized),
            findings=normalized,
            error_message=error_message,
            raw_output=raw_findings if status == "success" else None,
        )
    
    @staticmethod
    def map_severity(scanner_severity: str) -> SeverityLevel:
        """Map scanner-specific severity to normalized severity"""
        severity_map = {
            "critical": SeverityLevel.CRITICAL,
            "high": SeverityLevel.HIGH,
            "medium": SeverityLevel.MEDIUM,
            "low": SeverityLevel.LOW,
            "info": SeverityLevel.INFO,
            "informational": SeverityLevel.INFO,
            "warning": SeverityLevel.MEDIUM,
        }
        return severity_map.get(str(scanner_severity).lower(), SeverityLevel.MEDIUM)
