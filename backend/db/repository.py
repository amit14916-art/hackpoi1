import uuid
from typing import Optional, List
from sqlalchemy.orm import Session

from backend.db.models import Scan, FindingDB
from backend.models import (
    ScanResult,
    Finding,
    ScanStatus,
    ScanSummary,
    SeverityLevel,
)


def scan_model_to_result(scan_model: Scan) -> ScanResult:
    """Converts a SQLAlchemy Scan model into a Pydantic ScanResult."""
    findings_list: List[Finding] = []
    for f in scan_model.findings:
        findings_list.append(
            Finding(
                id=f.finding_id,
                name=f.name,
                category=f.category,
                severity=SeverityLevel(f.severity),
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                cwe_id=f.cwe_id,
                owasp_category=f.owasp_category,
                confidence=f.confidence,
                endpoint=f.endpoint,
                description=f.description,
                evidence=f.evidence,
                request_proof=f.request_proof,
                response_proof=f.response_proof,
                impact=f.impact or "",
                remediation_summary=f.remediation_summary or "",
                remediation_effort=f.remediation_effort or "LOW",
                remediation_code=f.remediation_code or {},
                references=f.references_list or [],
            )
        )

    summary_data = scan_model.findings_summary or {}
    summary = ScanSummary(**summary_data) if isinstance(summary_data, dict) else ScanSummary()

    return ScanResult(
        scan_id=scan_model.scan_id,
        target_url=scan_model.target_url,
        domain=scan_model.domain,
        status=ScanStatus(scan_model.status),
        current_step=scan_model.current_step,
        progress=scan_model.progress,
        started_at=scan_model.started_at,
        completed_at=scan_model.completed_at,
        score=scan_model.score,
        grade=scan_model.grade,
        findings_summary=summary,
        findings=findings_list,
        ai_summary=scan_model.ai_summary,
        executive_overview=scan_model.executive_overview,
        is_domain_verified=scan_model.is_domain_verified,
        error=scan_model.error,
    )


def save_or_update_scan(
    db: Session,
    result: ScanResult,
    org_id: Optional[str] = None,
    scan_type: str = "passive",
    framework_hint: Optional[str] = None,
    repo_full_name: Optional[str] = None,
) -> Scan:
    """Persists or updates a ScanResult and its associated Findings in Postgres."""
    scan = db.query(Scan).filter(Scan.scan_id == result.scan_id).first()
    summary_dict = result.findings_summary.model_dump() if hasattr(result.findings_summary, "model_dump") else dict(result.findings_summary)

    if not scan:
        scan = Scan(
            scan_id=result.scan_id,
            org_id=org_id,
            target_url=result.target_url,
            domain=result.domain,
            status=result.status.value if hasattr(result.status, "value") else str(result.status),
            current_step=result.current_step,
            progress=result.progress,
            started_at=result.started_at,
            completed_at=result.completed_at,
            score=result.score,
            grade=result.grade,
            findings_summary=summary_dict,
            ai_summary=result.ai_summary,
            executive_overview=result.executive_overview,
            is_domain_verified=result.is_domain_verified,
            error=result.error,
            scan_type=scan_type,
            framework_hint=framework_hint,
            repo_full_name=repo_full_name,
        )
        db.add(scan)
        db.flush()
    else:
        scan.status = result.status.value if hasattr(result.status, "value") else str(result.status)
        scan.current_step = result.current_step
        scan.progress = result.progress
        scan.completed_at = result.completed_at
        scan.score = result.score
        scan.grade = result.grade
        scan.findings_summary = summary_dict
        scan.ai_summary = result.ai_summary
        scan.executive_overview = result.executive_overview
        scan.is_domain_verified = result.is_domain_verified
        scan.error = result.error
        if org_id:
            scan.org_id = org_id
        if repo_full_name:
            scan.repo_full_name = repo_full_name

    # Synchronize findings
    existing_findings = {f.finding_id: f for f in scan.findings}
    for f in result.findings:
        f_id = f.id
        ref_list = f.references if hasattr(f, "references") else []
        rem_code = f.remediation_code if hasattr(f, "remediation_code") else {}
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)

        if f_id in existing_findings:
            db_f = existing_findings[f_id]
            db_f.name = f.name
            db_f.category = f.category
            db_f.severity = sev
            db_f.cvss_score = f.cvss_score
            db_f.cvss_vector = f.cvss_vector
            db_f.cwe_id = f.cwe_id
            db_f.owasp_category = f.owasp_category
            db_f.confidence = f.confidence
            db_f.endpoint = f.endpoint
            db_f.description = f.description
            db_f.evidence = f.evidence
            db_f.request_proof = f.request_proof
            db_f.response_proof = f.response_proof
            db_f.impact = f.impact
            db_f.remediation_summary = f.remediation_summary
            db_f.remediation_effort = f.remediation_effort
            db_f.remediation_code = rem_code
            db_f.references_list = ref_list
        else:
            db_f = FindingDB(
                id=uuid.uuid4().hex,
                finding_id=f_id,
                scan_id=scan.scan_id,
                name=f.name,
                category=f.category,
                severity=sev,
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                cwe_id=f.cwe_id,
                owasp_category=f.owasp_category,
                confidence=f.confidence,
                endpoint=f.endpoint,
                description=f.description,
                evidence=f.evidence,
                request_proof=f.request_proof,
                response_proof=f.response_proof,
                impact=f.impact,
                remediation_summary=f.remediation_summary,
                remediation_effort=f.remediation_effort,
                remediation_code=rem_code,
                references_list=ref_list,
            )
            db.add(db_f)

    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: str) -> Optional[ScanResult]:
    """Fetches a Scan from DB by scan_id and returns Pydantic ScanResult."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        return None
    return scan_model_to_result(scan)


def get_latest_completed_scan_for_domain(
    db: Session,
    domain: str,
    exclude_scan_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> Optional[ScanResult]:
    """Returns the most recent completed scan for the specified domain."""
    query = db.query(Scan).filter(
        Scan.domain == domain,
        Scan.status == ScanStatus.COMPLETED.value
    )
    if exclude_scan_id:
        query = query.filter(Scan.scan_id != exclude_scan_id)
    if org_id:
        query = query.filter(Scan.org_id == org_id)

    scan = query.order_by(Scan.started_at.desc()).first()
    if not scan:
        return None
    return scan_model_to_result(scan)
