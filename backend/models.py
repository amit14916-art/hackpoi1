from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    SCANNING = "SCANNING"
    ANALYZING_AI = "ANALYZING_AI"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class VerificationMethod(str, Enum):
    DNS_TXT = "DNS_TXT"
    HTTP_FILE = "HTTP_FILE"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"


class Finding(BaseModel):
    id: str
    name: str
    category: str  # "Security Headers", "SSL/TLS", "Information Disclosure", "CORS", "Cookie Security", "Injection", "XSS", "Secrets"
    severity: SeverityLevel
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None           # e.g., "CWE-79", "CWE-89", "CWE-798"
    owasp_category: Optional[str] = None   # e.g., "A03:2021-Injection", "A01:2021-Broken Access Control"
    confidence: str = "CERTAIN"            # "CERTAIN", "FIRM", "TENTATIVE"
    endpoint: str
    description: str
    evidence: Optional[str] = None
    request_proof: Optional[str] = None
    response_proof: Optional[str] = None
    impact: str = ""
    remediation_summary: str = ""
    remediation_effort: str = "LOW"        # "LOW", "MEDIUM", "HIGH"
    remediation_code: Dict[str, str] = Field(default_factory=dict)
    references: List[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    url: str
    scan_type: str = "passive"  # "passive" or "active"
    framework_hint: Optional[str] = "auto"  # "nginx", "apache", "express", "django", "auto"


class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    domain: str
    status: ScanStatus
    current_step: str = "Initializing"
    progress: int = 0
    started_at: str
    completed_at: Optional[str] = None
    score: int = 100
    grade: str = "A+"
    findings_summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: List[Finding] = Field(default_factory=list)
    ai_summary: Optional[str] = None
    executive_overview: Optional[str] = None
    is_domain_verified: bool = False
    error: Optional[str] = None


class VerificationChallenge(BaseModel):
    domain: str
    token: str
    dns_record_name: str
    dns_record_value: str
    http_file_path: str
    http_file_content: str
    created_at: str
    status: VerificationStatus = VerificationStatus.PENDING


class VerificationCheckRequest(BaseModel):
    domain: str
    token: str
    method: VerificationMethod = VerificationMethod.HTTP_FILE
