import uuid
import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.session import get_db
from backend.db.models import Domain, Scan, FindingDB, Organization
from backend.dashboard.schemas import (
    DomainCreate,
    DomainResponse,
    DomainHistoryItem,
    SeverityBreakdown,
    TrendMetrics,
    OrgOverviewResponse,
)
from backend.auth.dependencies import get_current_auth, require_role, AuthenticatedContext
from backend.verification.domain_verifier import DomainVerifier

router = APIRouter(prefix="/api/org", tags=["Organization Dashboard"])
verifier = DomainVerifier()


@router.post("/{org_id}/domains", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def add_domain_to_org(
    org_id: str,
    data: DomainCreate,
    auth: AuthenticatedContext = Depends(require_role("member")),
    db: Session = Depends(get_db),
):
    """Registers a new domain for organization-level monitoring and tracking."""
    if auth.org_id != org_id and not auth.has_role("admin"):
        raise HTTPException(status_code=403, detail="Cannot add domain to another organization.")

    clean_domain = verifier.normalize_domain(data.url)
    existing = db.query(Domain).filter(Domain.org_id == org_id, Domain.domain_name == clean_domain).first()
    if existing:
        return DomainResponse(
            id=existing.id,
            org_id=existing.org_id,
            url=existing.url,
            domain_name=existing.domain_name,
            is_domain_verified=existing.is_domain_verified,
            last_scan_id=existing.last_scan_id,
            latest_score=existing.last_scan.score if existing.last_scan else 100,
            latest_grade=existing.last_scan.grade if existing.last_scan else "A+",
            created_at=existing.created_at,
        )

    # Check if domain was previously verified
    is_verified = verifier.is_verified(clean_domain)
    # Check if a recent scan exists for this domain
    recent_scan = db.query(Scan).filter(Scan.domain == clean_domain).order_by(Scan.started_at.desc()).first()

    domain_id = f"dom_{uuid.uuid4().hex[:12]}"
    new_domain = Domain(
        id=domain_id,
        org_id=org_id,
        url=data.url.strip(),
        domain_name=clean_domain,
        is_domain_verified=is_verified,
        last_scan_id=recent_scan.scan_id if recent_scan else None,
        created_at=datetime.datetime.utcnow(),
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    return DomainResponse(
        id=new_domain.id,
        org_id=new_domain.org_id,
        url=new_domain.url,
        domain_name=new_domain.domain_name,
        is_domain_verified=new_domain.is_domain_verified,
        last_scan_id=new_domain.last_scan_id,
        latest_score=recent_scan.score if recent_scan else 100,
        latest_grade=recent_scan.grade if recent_scan else "A+",
        created_at=new_domain.created_at,
    )


@router.get("/{org_id}/domains", response_model=List[DomainResponse])
async def list_org_domains(
    org_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Lists all tracked domains for an organization along with latest score/grade."""
    if auth.org_id != org_id and not auth.has_role("admin"):
        raise HTTPException(status_code=403, detail="Cannot access other organizations' domains.")

    domains = db.query(Domain).filter(Domain.org_id == org_id).all()
    results: List[DomainResponse] = []
    for d in domains:
        score = 100
        grade = "A+"
        if d.last_scan:
            score = d.last_scan.score
            grade = d.last_scan.grade
        results.append(
            DomainResponse(
                id=d.id,
                org_id=d.org_id,
                url=d.url,
                domain_name=d.domain_name,
                is_domain_verified=d.is_domain_verified,
                last_scan_id=d.last_scan_id,
                latest_score=score,
                latest_grade=grade,
                created_at=d.created_at,
            )
        )
    return results


@router.get("/{org_id}/domains/{domain_id}/history", response_model=List[DomainHistoryItem])
async def get_domain_scan_history(
    org_id: str,
    domain_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Returns historical risk score and finding timeline for a specific domain.
    Used for recharts / chart.js trend visualization.
    """
    if auth.org_id != org_id and not auth.has_role("admin"):
        raise HTTPException(status_code=403, detail="Cannot access other organizations.")

    domain = db.query(Domain).filter(Domain.id == domain_id, Domain.org_id == org_id).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Tracked domain not found.")

    scans = (
        db.query(Scan)
        .filter(Scan.domain == domain.domain_name)
        .order_by(Scan.started_at.asc())
        .all()
    )

    history: List[DomainHistoryItem] = []
    for s in scans:
        summary = s.findings_summary or {}
        counts = {
            "critical": summary.get("critical", 0),
            "high": summary.get("high", 0),
            "medium": summary.get("medium", 0),
            "low": summary.get("low", 0),
            "info": summary.get("info", 0),
            "total": summary.get("total", 0),
        }
        history.append(
            DomainHistoryItem(
                scan_id=s.scan_id,
                timestamp=s.completed_at or s.started_at,
                score=s.score,
                grade=s.grade,
                findings_count=counts,
            )
        )
    return history


@router.get("/{org_id}/overview", response_model=OrgOverviewResponse)
async def get_org_overview(
    org_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Aggregates organization-wide security posture:
    Total domains, average risk score, open findings by severity, and 7d/30d trends.
    """
    if auth.org_id != org_id and not auth.has_role("admin"):
        raise HTTPException(status_code=403, detail="Cannot access other organizations.")

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")

    domains = db.query(Domain).filter(Domain.org_id == org_id).all()
    total_domains = len(domains)
    verified_domains = sum(1 for d in domains if d.is_domain_verified)

    # Scans for this org
    scans = db.query(Scan).filter(Scan.org_id == org_id).order_by(Scan.started_at.desc()).all()
    if not scans and domains:
        # Fallback to query scans by domain names if scans were created before org linking
        domain_names = [d.domain_name for d in domains]
        scans = db.query(Scan).filter(Scan.domain.in_(domain_names)).order_by(Scan.started_at.desc()).all()

    avg_score = 100.0
    if scans:
        avg_score = sum(s.score for s in scans) / len(scans)

    # Open findings across latest scans per domain
    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for d in domains:
        if d.last_scan:
            s_sum = d.last_scan.findings_summary or {}
            for k in ["critical", "high", "medium", "low", "info", "total"]:
                severity_totals[k] += s_sum.get(k, 0)

    # Calculate 7d and 30d deltas
    now = datetime.datetime.utcnow()
    t_7d = (now - datetime.timedelta(days=7)).isoformat()
    t_30d = (now - datetime.timedelta(days=30)).isoformat()

    scans_recent = [s for s in scans if s.started_at >= t_7d]
    scans_older = [s for s in scans if s.started_at < t_7d and s.started_at >= t_30d]

    avg_recent = (sum(s.score for s in scans_recent) / len(scans_recent)) if scans_recent else avg_score
    avg_older = (sum(s.score for s in scans_older) / len(scans_older)) if scans_older else avg_score

    delta_7d = round(avg_recent - avg_older, 1)
    delta_30d = round(avg_score - avg_older, 1)

    return OrgOverviewResponse(
        org_id=org.id,
        org_name=org.name,
        total_domains=total_domains,
        verified_domains=verified_domains,
        avg_score=round(avg_score, 1),
        total_open_findings=SeverityBreakdown(**severity_totals),
        trends=TrendMetrics(
            delta_7d=delta_7d,
            delta_30d=delta_30d,
            scan_count_7d=len(scans_recent),
            scan_count_30d=len([s for s in scans if s.started_at >= t_30d]),
        ),
    )
