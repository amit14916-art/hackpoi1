import os
import uuid
import hmac
import hashlib
import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from fastapi import APIRouter, Request, Header, HTTPException, Depends, BackgroundTasks, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import WebhookEndpoint, Organization, Scan
from backend.models import ScanRequest, ScanResult, Finding
from backend.auth.dependencies import get_current_auth, require_role, AuthenticatedContext
from backend.notifications.dispatcher import NotificationDispatcher

logger = logging.getLogger("secops.cicd")
router = APIRouter(prefix="/api/integrations/cicd", tags=["CI/CD Continuous Scanning"])
webhook_router = APIRouter(prefix="/api/webhooks", tags=["CI/CD Webhooks"])

dispatcher = NotificationDispatcher()


# ==========================================
# Finding Diffing Logic
# ==========================================

def _finding_fingerprint(finding: Finding) -> str:
    """Computes a unique fingerprint for a finding based on CWE + endpoint."""
    cwe = finding.cwe_id or finding.name
    endpoint = finding.endpoint.strip().lower()
    return f"{cwe}::{endpoint}"


def diff_findings(
    current_findings: List[Finding],
    previous_findings: List[Finding],
) -> Tuple[List[Finding], List[Finding]]:
    """
    Diffs findings between current scan and previous scan for the same domain.
    Returns: (new_findings, resolved_findings)
    """
    prev_map = {_finding_fingerprint(f): f for f in previous_findings}
    curr_map = {_finding_fingerprint(f): f for f in current_findings}

    new_findings = [f for key, f in curr_map.items() if key not in prev_map]
    resolved_findings = [f for key, f in prev_map.items() if key not in curr_map]

    return new_findings, resolved_findings


# ==========================================
# Signature Verification
# ==========================================

def verify_webhook_token(
    provider: str,
    secret_token: str,
    body_bytes: bytes,
    headers: Dict[str, str],
) -> bool:
    """Verifies incoming webhook authentication according to provider."""
    # 1. GitHub Actions: X-Hub-Signature-256 or Authorization
    if provider == "github_actions":
        sig = headers.get("x-hub-signature-256")
        if sig and sig.startswith("sha256="):
            expected = "sha256=" + hmac.new(
                secret_token.encode("utf-8"),
                body_bytes,
                hashlib.sha256
            ).hexdigest()
            if hmac.compare_digest(expected, sig):
                return True
        # Check X-SecOps-Token or Bearer
        token = headers.get("x-secops-token") or headers.get("authorization", "").replace("Bearer ", "").strip()
        return hmac.compare_digest(secret_token, token)

    # 2. GitLab CI: X-Gitlab-Token
    elif provider == "gitlab_ci":
        gitlab_token = headers.get("x-gitlab-token", "").strip()
        if gitlab_token and hmac.compare_digest(secret_token, gitlab_token):
            return True
        # Also check Authorization header
        token = headers.get("authorization", "").replace("Bearer ", "").strip()
        return hmac.compare_digest(secret_token, token)

    # 3. Generic webhook: X-Webhook-Secret or Authorization Bearer
    token = (
        headers.get("x-webhook-secret")
        or headers.get("x-secops-token")
        or headers.get("authorization", "").replace("Bearer ", "").strip()
    )
    if token and hmac.compare_digest(secret_token, token):
        return True

    # If payload contains secret_token field
    try:
        data = json.loads(body_bytes.decode("utf-8"))
        if data.get("secret_token") and hmac.compare_digest(secret_token, str(data.get("secret_token"))):
            return True
    except Exception:
        pass

    return False


# ==========================================
# Webhook Deployment Endpoint
# ==========================================

@webhook_router.post("/deploy/{org_id}", status_code=status.HTTP_202_ACCEPTED)
async def trigger_deploy_scan(
    org_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Generic & Provider-Specific CI/CD Webhook.
    Triggers an automated security scan for the domain associated with the deployment.
    """
    body_bytes = await request.body()
    headers_lower = {k.lower(): v for k, v in request.headers.items()}

    # Find registered WebhookEndpoints for this org
    endpoints = db.query(WebhookEndpoint).filter(WebhookEndpoint.org_id == org_id).all()
    if not endpoints:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No webhook endpoints registered for organization {org_id}."
        )

    # Validate against matching endpoint
    matched_endpoint: Optional[WebhookEndpoint] = None
    for ep in endpoints:
        if verify_webhook_token(ep.provider, ep.secret_token, body_bytes, headers_lower):
            matched_endpoint = ep
            break

    if not matched_endpoint:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature or token for deployment scan."
        )

    # Parse optional overrides from body
    target_domain = matched_endpoint.target_domain
    scan_type = "passive"
    framework_hint = "auto"

    try:
        if body_bytes:
            data = json.loads(body_bytes.decode("utf-8"))
            if data.get("target_domain"):
                target_domain = data.get("target_domain")
            if data.get("scan_type"):
                scan_type = data.get("scan_type")
            if data.get("framework_hint"):
                framework_hint = data.get("framework_hint")
    except Exception:
        pass

    # Import main application pipeline runner
    from backend.main import start_scan_job

    target_url = target_domain if target_domain.startswith("http") else f"https://{target_domain}"
    scan_req = ScanRequest(
        url=target_url,
        scan_type=scan_type,
        framework_hint=framework_hint,
    )

    scan_info = await start_scan_job(
        scan_req=scan_req,
        org_id=org_id,
        background_tasks=background_tasks,
        db=db,
    )

    return {
        "status": "scan_triggered",
        "org_id": org_id,
        "scan_id": scan_info["scan_id"],
        "target_url": scan_info["target_url"],
        "provider": matched_endpoint.provider,
    }


# ==========================================
# CI/CD Endpoints & Notification Settings API
# ==========================================

class WebhookEndpointCreate(BaseModel):
    provider: str = Field("generic", pattern="^(generic|github_actions|gitlab_ci)$")
    target_domain: str = Field(..., min_length=3)
    secret_token: Optional[str] = None


class WebhookEndpointResponse(BaseModel):
    id: str
    org_id: str
    provider: str
    target_domain: str
    secret_token: str

    class Config:
        from_attributes = True


class NotificationSettingsUpdate(BaseModel):
    slack_webhook_url: Optional[str] = None
    notify_on_new_findings: Optional[bool] = None
    min_severity_to_notify: Optional[str] = Field(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")


@router.post("/endpoints", response_model=WebhookEndpointResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook_endpoint(
    data: WebhookEndpointCreate,
    auth: AuthenticatedContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Registers a new CI/CD deployment webhook endpoint for automated scanning."""
    secret = data.secret_token or f"secops_whsec_{uuid.uuid4().hex}"
    ep_id = f"ep_{uuid.uuid4().hex[:12]}"

    ep = WebhookEndpoint(
        id=ep_id,
        org_id=auth.org_id,
        provider=data.provider,
        target_domain=data.target_domain.strip().lower(),
        secret_token=secret,
    )
    db.add(ep)
    db.commit()
    db.refresh(ep)
    return ep


@router.get("/endpoints", response_model=List[WebhookEndpointResponse])
async def list_webhook_endpoints(
    auth: AuthenticatedContext = Depends(require_role("member")),
    db: Session = Depends(get_db),
):
    endpoints = db.query(WebhookEndpoint).filter(WebhookEndpoint.org_id == auth.org_id).all()
    return endpoints


@router.patch("/notifications")
async def update_notification_settings(
    settings: NotificationSettingsUpdate,
    auth: AuthenticatedContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Updates organization Slack webhook URL and severity alert thresholds."""
    org = db.query(Organization).filter(Organization.id == auth.org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")

    if settings.slack_webhook_url is not None:
        org.slack_webhook_url = settings.slack_webhook_url
    if settings.notify_on_new_findings is not None:
        org.notify_on_new_findings = settings.notify_on_new_findings
    if settings.min_severity_to_notify is not None:
        org.min_severity_to_notify = settings.min_severity_to_notify

    db.commit()
    db.refresh(org)
    return {
        "status": "settings_updated",
        "slack_webhook_url": org.slack_webhook_url,
        "notify_on_new_findings": org.notify_on_new_findings,
        "min_severity_to_notify": org.min_severity_to_notify,
    }
