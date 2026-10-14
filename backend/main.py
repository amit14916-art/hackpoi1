import os
import uuid
import asyncio
import datetime
from typing import Dict, Optional, Any
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Response, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, PlainTextResponse, FileResponse
from sqlalchemy.orm import Session

from backend.db.session import get_db, init_db, SessionLocal
from backend.db.models import Scan, FindingDB, Organization, Domain, DomainRepoMapping
from backend.db.repository import save_or_update_scan, get_scan, get_latest_completed_scan_for_domain
from backend.auth.dependencies import get_current_auth, require_role, AuthenticatedContext
from backend.auth.router import router as auth_router
from backend.auth.sso import router as sso_router
from backend.integrations.github_app import router as github_router, GitHubAppService
from backend.integrations.cicd import router as cicd_router, webhook_router, diff_findings, dispatcher
from backend.dashboard.router import router as dashboard_router

from backend.models import (
    ScanRequest,
    ScanResult,
    ScanStatus,
    VerificationChallenge,
    VerificationCheckRequest,
    VerificationStatus,
)
from backend.scanners.engine import ScannerEngine
from backend.verification.domain_verifier import DomainVerifier
from backend.ai.remediation_engine import AIRemediationEngine
from backend.reporting.report_generator import ReportGenerator


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables on startup
    init_db()
    yield


app = FastAPI(
    title="AI-Powered Security Audit & DAST Platform",
    description="Automated web security auditing, legal domain verification guardrails, and AI-driven remediation.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for local dev / decoupled setups / file protocol
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Services
verifier = DomainVerifier()
scanner_engine = ScannerEngine(domain_verifier=verifier)
ai_engine = AIRemediationEngine()

# Scan Jobs Cache (backed by database persistence)
scan_jobs: Dict[str, ScanResult] = {}


# Include Enterprise Feature Routers
app.include_router(auth_router)
app.include_router(sso_router)
app.include_router(github_router)
app.include_router(cicd_router)
app.include_router(webhook_router)
app.include_router(dashboard_router)


async def _execute_scan_pipeline(scan_id: str, request: ScanRequest, org_id: Optional[str] = None):
    def update_progress(pct: int, step_desc: str):
        if scan_id in scan_jobs:
            scan_jobs[scan_id].progress = pct
            scan_jobs[scan_id].current_step = step_desc
            # Update DB
            db = SessionLocal()
            try:
                s = db.query(Scan).filter(Scan.scan_id == scan_id).first()
                if s:
                    s.progress = pct
                    s.current_step = step_desc
                    db.commit()
            finally:
                db.close()

    try:
        # Phase 1: Run Passive Suite (+ Active if verified)
        result = await scanner_engine.run_scan(
            scan_id=scan_id,
            raw_url=request.url,
            scan_type=request.scan_type,
            on_progress=update_progress,
        )

        # Phase 2: AI Remediation Layer
        update_progress(90, "Synthesizing AI Executive Briefing & Remediation Patches")
        enriched_result = await ai_engine.analyze_and_enrich(result, framework_hint=request.framework_hint or "auto")

        enriched_result.status = ScanStatus.COMPLETED
        enriched_result.progress = 100
        enriched_result.current_step = "Audit Complete"
        enriched_result.completed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        scan_jobs[scan_id] = enriched_result

        # Phase 3: Persist to Postgres database
        db = SessionLocal()
        try:
            # Query previous scan to compute new vs resolved findings (Feature 2)
            prev_scan = get_latest_completed_scan_for_domain(
                db=db,
                domain=enriched_result.domain,
                exclude_scan_id=scan_id,
                org_id=org_id,
            )

            # Save completed scan
            saved_scan = save_or_update_scan(
                db=db,
                result=enriched_result,
                org_id=org_id,
                scan_type=request.scan_type,
                framework_hint=request.framework_hint,
            )

            # Update tracked domain in dashboard (Feature 4)
            if org_id:
                domain_rec = db.query(Domain).filter(
                    Domain.org_id == org_id,
                    Domain.domain_name == enriched_result.domain
                ).first()
                if domain_rec:
                    domain_rec.last_scan_id = scan_id
                    domain_rec.is_domain_verified = enriched_result.is_domain_verified
                    db.commit()

            # Feature 1: Auto-PR Remediation via GitHub App
            # Only trigger when domain is verified and findings exist
            if enriched_result.is_domain_verified and enriched_result.findings and org_id:
                org = db.query(Organization).filter(Organization.id == org_id).first()
                if org and org.github_installation_id:
                    mapping = db.query(DomainRepoMapping).filter(
                        DomainRepoMapping.org_id == org_id,
                        DomainRepoMapping.domain == enriched_result.domain
                    ).first()
                    if mapping:
                        repo_full_name = mapping.repo_full_name
                        default_branch = mapping.default_branch or "main"
                        for finding in enriched_result.findings:
                            if finding.remediation_code:
                                pr_result = await GitHubAppService.create_branch_and_pr(
                                    installation_id=org.github_installation_id,
                                    repo_full_name=repo_full_name,
                                    finding=finding,
                                    default_branch=default_branch,
                                    framework_hint=request.framework_hint,
                                )
                                if pr_result:
                                    db_f = db.query(FindingDB).filter(
                                        FindingDB.scan_id == scan_id,
                                        FindingDB.finding_id == finding.id
                                    ).first()
                                    if db_f:
                                        db_f.pr_url = pr_result.get("pr_url")
                                        db_f.pr_status = pr_result.get("pr_status")
                                        db_f.pr_branch = pr_result.get("pr_branch")
                                        db.commit()

            # Feature 2: Diff findings & Notification dispatch
            if org_id:
                previous_findings = prev_scan.findings if prev_scan else []
                new_findings, resolved_findings = diff_findings(enriched_result.findings, previous_findings)
                
                if new_findings:
                    # Determine highest severity among new findings
                    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                    highest_sev = "INFO"
                    for s in sev_order:
                        if any(f.severity.value == s or str(f.severity) == s for f in new_findings):
                            highest_sev = s
                            break

                    top_f = [
                        {"name": f.name, "severity": f.severity.value, "cwe_id": f.cwe_id or "N/A"}
                        for f in new_findings[:5]
                    ]
                    alert_msg = f"{len(new_findings)} new vulnerabilities detected (highest severity: {highest_sev})."
                    asyncio.create_task(
                        dispatcher.dispatch(
                            org_id=org_id,
                            message=alert_msg,
                            severity=highest_sev,
                            details={
                                "domain": enriched_result.domain,
                                "scan_id": scan_id,
                                "new_findings_count": len(new_findings),
                                "resolved_findings_count": len(resolved_findings),
                                "top_findings": top_f,
                            },
                        )
                    )
        finally:
            db.close()

    except Exception as e:
        if scan_id in scan_jobs:
            scan_jobs[scan_id].status = ScanStatus.FAILED
            scan_jobs[scan_id].error = str(e)
            scan_jobs[scan_id].current_step = f"Scan failed: {str(e)}"
        
        db = SessionLocal()
        try:
            s = db.query(Scan).filter(Scan.scan_id == scan_id).first()
            if s:
                s.status = ScanStatus.FAILED.value
                s.error = str(e)
                s.current_step = f"Scan failed: {str(e)}"
                db.commit()
        finally:
            db.close()


async def start_scan_job(
    scan_req: ScanRequest,
    org_id: Optional[str],
    background_tasks: BackgroundTasks,
    db: Session,
) -> Dict[str, Any]:
    """Helper to initialize and schedule a scan job."""
    url = scan_req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    normalized_target = scanner_engine.normalize_url(url)
    clean_domain = verifier.normalize_domain(url)
    is_v = verifier.is_verified(url)

    placeholder_result = ScanResult(
        scan_id=scan_id,
        target_url=normalized_target,
        domain=clean_domain,
        status=ScanStatus.QUEUED,
        current_step="Queued in background task runner",
        progress=5,
        started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        is_domain_verified=is_v,
    )

    # Persist in DB and memory
    scan_jobs[scan_id] = placeholder_result
    save_or_update_scan(
        db=db,
        result=placeholder_result,
        org_id=org_id,
        scan_type=scan_req.scan_type,
        framework_hint=scan_req.framework_hint,
    )

    background_tasks.add_task(_execute_scan_pipeline, scan_id, scan_req, org_id)

    return {
        "scan_id": scan_id,
        "target_url": normalized_target,
        "status": ScanStatus.QUEUED,
        "is_domain_verified": is_v,
    }


# ==========================================
# REST API Endpoints
# ==========================================

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "gemini_api_configured": bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")),
        "active_jobs_count": len(scan_jobs),
    }


@app.post("/api/scan/start")
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    auth: AuthenticatedContext = Depends(require_role("member")),
    db: Session = Depends(get_db),
):
    return await start_scan_job(
        scan_req=request,
        org_id=auth.org_id,
        background_tasks=background_tasks,
        db=db,
    )


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(
    scan_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    # Check cache first, then database
    job = scan_jobs.get(scan_id) or get_scan(db, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return {
        "scan_id": job.scan_id,
        "status": job.status,
        "progress": job.progress,
        "current_step": job.current_step,
        "score": job.score,
        "grade": job.grade,
        "error": job.error,
    }


@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    job = scan_jobs.get(scan_id) or get_scan(db, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return job


@app.get("/api/scan/{scan_id}/export/markdown")
async def export_markdown_report(
    scan_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    job = scan_jobs.get(scan_id) or get_scan(db, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    md_content = ReportGenerator.to_markdown(job)
    filename = f"security_audit_{job.domain}.md"
    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{scan_id}/export/html")
async def export_html_report(
    scan_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    job = scan_jobs.get(scan_id) or get_scan(db, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    html_content = ReportGenerator.to_printable_html(job)
    return HTMLResponse(content=html_content)


@app.get("/api/scan/{scan_id}/export/compliance")
async def export_compliance_report(
    scan_id: str,
    framework: str = Query("soc2", pattern="^(soc2|iso27001)$"),
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Exports an executive compliance mapping PDF report for SOC 2 Type II or ISO 27001:2022.
    """
    job = scan_jobs.get(scan_id) or get_scan(db, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    org = db.query(Organization).filter(Organization.id == auth.org_id).first()
    org_name = org.name if org else "Enterprise Organization"

    if framework == "soc2":
        pdf_bytes = ReportGenerator.to_soc2_report(job, org_name)
    else:
        pdf_bytes = ReportGenerator.to_iso27001_report(job, org_name)

    filename = f"compliance_{framework}_{job.domain}_{job.scan_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ==========================================
# Domain Verification (Legal Guardrail)
# ==========================================

@app.post("/api/verify/generate")
async def generate_verification(
    domain: str = Query(..., description="Domain name or URL to verify"),
    auth: AuthenticatedContext = Depends(require_role("member")),
):
    challenge = verifier.create_challenge(domain)
    return challenge


@app.post("/api/verify/check")
async def check_verification(
    req: VerificationCheckRequest,
    auth: AuthenticatedContext = Depends(require_role("member")),
):
    success, message = await verifier.verify(req.domain, req.token, method=req.method)
    return {
        "domain": verifier.normalize_domain(req.domain),
        "verified": success,
        "message": message,
        "status": VerificationStatus.VERIFIED if success else VerificationStatus.FAILED,
    }


@app.get("/api/verify/status")
async def check_domain_status(
    domain: str = Query(...),
    auth: AuthenticatedContext = Depends(get_current_auth),
):
    is_v = verifier.is_verified(domain)
    return {
        "domain": verifier.normalize_domain(domain),
        "verified": is_v,
    }


# ==========================================
# Frontend Dashboard Mounting
# ==========================================

frontend_dir = Path(__file__).parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/styles.css")
    async def serve_styles():
        css_file = frontend_dir / "styles.css"
        if css_file.exists():
            return FileResponse(str(css_file), media_type="text/css")
        raise HTTPException(status_code=404, detail="styles.css not found")

    @app.get("/app.js")
    async def serve_app_js():
        js_file = frontend_dir / "app.js"
        if js_file.exists():
            return FileResponse(str(js_file), media_type="application/javascript")
        raise HTTPException(status_code=404, detail="app.js not found")

    @app.get("/", response_class=HTMLResponse)
    async def serve_dashboard():
        index_file = frontend_dir / "index.html"
        if index_file.exists():
            return FileResponse(str(index_file))
        return HTMLResponse("<h1>Frontend dashboard index.html not found.</h1>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
