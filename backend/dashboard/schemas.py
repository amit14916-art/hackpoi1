from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class DomainCreate(BaseModel):
    url: str = Field(..., description="Target domain or URL to track, e.g. https://example.com")


class DomainResponse(BaseModel):
    id: str
    org_id: str
    url: str
    domain_name: str
    is_domain_verified: bool
    last_scan_id: Optional[str] = None
    latest_score: Optional[int] = 100
    latest_grade: Optional[str] = "A+"
    created_at: datetime

    class Config:
        from_attributes = True


class DomainHistoryItem(BaseModel):
    scan_id: str
    timestamp: str
    score: int
    grade: str
    findings_count: Dict[str, int]  # {"critical": 0, "high": 1, ...}


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class TrendMetrics(BaseModel):
    delta_7d: float = 0.0
    delta_30d: float = 0.0
    scan_count_7d: int = 0
    scan_count_30d: int = 0


class OrgOverviewResponse(BaseModel):
    org_id: str
    org_name: str
    total_domains: int
    verified_domains: int
    avg_score: float
    total_open_findings: SeverityBreakdown
    trends: TrendMetrics
