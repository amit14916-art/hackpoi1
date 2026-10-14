import os
import time
import json
import hmac
import hashlib
import base64
import logging
from typing import Optional, Dict, Any, Tuple
import httpx
from fastapi import APIRouter, Request, HTTPException, Depends, Header, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import Organization, DomainRepoMapping, FindingDB
from backend.auth.dependencies import get_current_auth, require_role, AuthenticatedContext
from backend.models import Finding

logger = logging.getLogger("secops.github_app")
router = APIRouter(prefix="/api/integrations/github", tags=["GitHub App Integration"])

GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
GITHUB_PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY")  # PEM string or path to .pem
GITHUB_APP_SLUG = os.getenv("GITHUB_APP_SLUG", "secops-guardian")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")


class RepoMappingCreate(BaseModel):
    domain: str = Field(..., description="Target domain, e.g. example.com")
    repo_full_name: str = Field(..., description="GitHub repository full name, e.g. owner/repo")
    default_branch: str = Field("main", description="Default branch to target PRs against")


class GitHubConnectResponse(BaseModel):
    install_url: str
    app_slug: str
    app_id: Optional[str] = None
    configured: bool


class GitHubAppService:
    @staticmethod
    def is_configured() -> bool:
        return bool(GITHUB_APP_ID and GITHUB_PRIVATE_KEY)

    @staticmethod
    def get_private_key_pem() -> Optional[bytes]:
        if not GITHUB_PRIVATE_KEY:
            return None
        # Check if it's a file path
        if os.path.exists(GITHUB_PRIVATE_KEY):
            with open(GITHUB_PRIVATE_KEY, "rb") as f:
                return f.read()
        # Otherwise treat as PEM content
        pem = GITHUB_PRIVATE_KEY.strip()
        # Handle cases where newlines were escaped
        if "\\n" in pem:
            pem = pem.replace("\\n", "\n")
        return pem.encode("utf-8")

    @classmethod
    def generate_jwt(cls) -> str:
        """Generates RS256 JWT for GitHub App authentication."""
        pem_bytes = cls.get_private_key_pem()
        if not pem_bytes or not GITHUB_APP_ID:
            raise ValueError("GitHub App ID or Private Key is not configured.")

        import jwt
        from cryptography.hazmat.primitives import serialization

        private_key = serialization.load_pem_private_key(pem_bytes, password=None)
        now = int(time.time())
        payload = {
            "iat": now - 60,
            "exp": now + (10 * 60),
            "iss": GITHUB_APP_ID,
        }
        return jwt.encode(payload, private_key, algorithm="RS256")

    @classmethod
    async def get_installation_token(cls, installation_id: str) -> Optional[str]:
        """Exchanges App JWT for an installation access token."""
        if not cls.is_configured():
            return None
        try:
            app_jwt = cls.generate_jwt()
            headers = {
                "Authorization": f"Bearer {app_jwt}",
                "Accept": "application/vnd.github.v3+json",
            }
            url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, headers=headers)
                if resp.status_code == 201:
                    return resp.json().get("token")
                logger.error(f"GitHub token exchange failed: {resp.status_code} - {resp.text}")
                return None
        except Exception as e:
            logger.error(f"Error fetching GitHub installation token: {str(e)}")
            return None

    @classmethod
    def verify_webhook_signature(cls, payload_bytes: bytes, signature_header: Optional[str]) -> bool:
        """Verifies GitHub X-Hub-Signature-256 HMAC."""
        if not GITHUB_WEBHOOK_SECRET:
            # If secret not set in dev, log warning but do not crash
            logger.warning("GITHUB_WEBHOOK_SECRET is empty. Skipping signature verification.")
            return True
        if not signature_header or not signature_header.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(
            GITHUB_WEBHOOK_SECRET.encode("utf-8"),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature_header)

    @classmethod
    def infer_patch_file_path(cls, finding: Finding, framework_hint: Optional[str] = None) -> str:
        """Determines best file path in repository to apply the remediation patch."""
        hint = (framework_hint or "").lower()
        cat = (finding.category or "").lower()

        if "nginx" in hint:
            return "nginx.conf"
        elif "apache" in hint:
            return ".htaccess"
        elif "django" in hint:
            return "settings.py"
        elif "express" in hint or "node" in hint:
            return "server.js"
        
        # Category heuristics
        if "header" in cat or "cors" in cat or "ssl" in cat:
            return "security_headers.conf"
        elif "secret" in cat:
            return ".env.example"
        elif "injection" in cat or "sqli" in cat or "xss" in cat:
            return f"patches/fix_{finding.id.lower().replace('-', '_')}.patch"
        return f"secops_remediation/{finding.id}.patch"

    @classmethod
    async def create_branch_and_pr(
        cls,
        installation_id: str,
        repo_full_name: str,
        finding: Finding,
        default_branch: str = "main",
        framework_hint: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Creates a fix branch, commits the remediation patch, and opens a GitHub PR.
        Never auto-merges.
        """
        token = await cls.get_installation_token(installation_id)
        if not token:
            logger.warning("Could not acquire GitHub installation token. Skipping PR creation.")
            return None

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        }
        api_base = f"https://api.github.com/repos/{repo_full_name}"

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                # 1. Fetch default branch commit SHA
                ref_resp = await client.get(f"{api_base}/git/ref/heads/{default_branch}", headers=headers)
                if ref_resp.status_code != 200:
                    logger.error(f"Failed to fetch default branch {default_branch}: {ref_resp.status_code}")
                    return None
                base_sha = ref_resp.json()["object"]["sha"]

                # 2. Create fix branch
                branch_name = f"secops-fix/{finding.id.lower()}"
                create_ref_resp = await client.post(
                    f"{api_base}/git/refs",
                    headers=headers,
                    json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
                )
                if create_ref_resp.status_code not in (201, 422):
                    logger.error(f"Failed to create branch {branch_name}: {create_ref_resp.text}")
                    return None

                # 3. Formulate patch code content
                patch_file_path = cls.infer_patch_file_path(finding, framework_hint)
                patch_content = ""
                if finding.remediation_code:
                    for lang, code in finding.remediation_code.items():
                        patch_content += f"# Remediation for {lang}:\n{code}\n\n"
                if not patch_content:
                    patch_content = f"# SecOps Remediation:\n# {finding.remediation_summary}\n"

                encoded_content = base64.b64encode(patch_content.encode("utf-8")).decode("utf-8")

                # Check if file exists on branch to supply SHA if updating
                file_sha = None
                get_file_resp = await client.get(
                    f"{api_base}/contents/{patch_file_path}?ref={branch_name}",
                    headers=headers
                )
                if get_file_resp.status_code == 200:
                    file_sha = get_file_resp.json().get("sha")

                put_payload: Dict[str, Any] = {
                    "message": f"SecOps Guardian: Automated patch for {finding.name} [{finding.cwe_id or 'VULN'}]",
                    "content": encoded_content,
                    "branch": branch_name,
                }
                if file_sha:
                    put_payload["sha"] = file_sha

                put_resp = await client.put(
                    f"{api_base}/contents/{patch_file_path}",
                    headers=headers,
                    json=put_payload,
                )
                if put_resp.status_code not in (200, 201):
                    logger.error(f"Failed to commit file to {branch_name}: {put_resp.text}")
                    return None

                # 4. Open Pull Request
                pr_title = f"[SecOps Guardian] Fix: {finding.name}"
                pr_body = (
                    f"## 🛡️ SecOps Guardian Automated Security Remediation\n\n"
                    f"**Vulnerability:** {finding.name}\n"
                    f"**Severity:** `{finding.severity}` | **CVSS Score:** `{finding.cvss_score}`\n"
                    f"**CWE:** `{finding.cwe_id or 'N/A'}` | **OWASP Category:** `{finding.owasp_category or 'N/A'}`\n"
                    f"**Affected Endpoint:** `{finding.endpoint}`\n\n"
                    f"### 📋 Remediation Summary\n{finding.remediation_summary}\n\n"
                    f"### 🔬 Technical Request & Response Proof\n"
                    f"**Request Proof:**\n```http\n{finding.request_proof or 'N/A'}\n```\n\n"
                    f"**Response Proof:**\n```http\n{finding.response_proof or 'N/A'}\n```\n\n"
                    f"### ⚠️ Deployment Guardrail\n"
                    f"- **Auto-Merge Disabled:** Review and run all CI/CD regression tests before merging.\n"
                    f"- Proposed changes committed to `{patch_file_path}`.\n"
                )

                pr_resp = await client.post(
                    f"{api_base}/pulls",
                    headers=headers,
                    json={
                        "title": pr_title,
                        "head": branch_name,
                        "base": default_branch,
                        "body": pr_body,
                        "maintainer_can_modify": True,
                    }
                )

                if pr_resp.status_code == 201:
                    pr_data = pr_resp.json()
                    return {
                        "pr_url": pr_data.get("html_url"),
                        "pr_number": pr_data.get("number"),
                        "pr_status": "open",
                        "pr_branch": branch_name,
                    }
                elif pr_resp.status_code == 422 and "A pull request already exists" in pr_resp.text:
                    # Find existing PR
                    existing_prs = await client.get(
                        f"{api_base}/pulls?head={repo_full_name.split('/')[0]}:{branch_name}&state=open",
                        headers=headers
                    )
                    if existing_prs.status_code == 200 and existing_prs.json():
                        pr_data = existing_prs.json()[0]
                        return {
                            "pr_url": pr_data.get("html_url"),
                            "pr_number": pr_data.get("number"),
                            "pr_status": "open",
                            "pr_branch": branch_name,
                        }
                logger.error(f"Failed to create PR: {pr_resp.status_code} - {pr_resp.text}")
                return None
            except Exception as e:
                logger.error(f"Error executing GitHub PR automation: {str(e)}")
                return None


# ==========================================
# REST API Endpoints
# ==========================================

@router.get("/status", response_model=Dict[str, Any])
async def get_github_integration_status(
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    org = db.query(Organization).filter(Organization.id == auth.org_id).first()
    return {
        "app_configured": GitHubAppService.is_configured(),
        "app_slug": GITHUB_APP_SLUG,
        "installation_id": org.github_installation_id if org else None,
        "connected": bool(org and org.github_installation_id),
    }


@router.post("/connect", response_model=GitHubConnectResponse)
async def connect_github_app(
    auth: AuthenticatedContext = Depends(require_role("admin")),
):
    """Returns the GitHub App installation URL for the organization admin."""
    install_url = f"https://github.com/apps/{GITHUB_APP_SLUG}/installations/new?state={auth.org_id}"
    return GitHubConnectResponse(
        install_url=install_url,
        app_slug=GITHUB_APP_SLUG,
        app_id=GITHUB_APP_ID,
        configured=GitHubAppService.is_configured(),
    )


@router.post("/webhook")
async def github_webhook_receiver(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Webhook receiver for GitHub App installation events."""
    body_bytes = await request.body()
    if not GitHubAppService.verify_webhook_signature(body_bytes, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature.")

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON payload.")

    event = x_github_event or payload.get("action")
    action = payload.get("action")

    # Handle installation created / deleted
    if event == "installation" or "installation" in payload:
        installation = payload.get("installation", {})
        installation_id = str(installation.get("id"))
        
        # Check if state was passed with org_id
        target_org_id = payload.get("state")
        
        if action == "created":
            logger.info(f"GitHub App installed: ID {installation_id}")
            if target_org_id:
                org = db.query(Organization).filter(Organization.id == target_org_id).first()
                if org:
                    org.github_installation_id = installation_id
                    db.commit()
            return {"status": "installation_registered", "installation_id": installation_id}
            
        elif action == "deleted":
            logger.info(f"GitHub App uninstalled: ID {installation_id}")
            orgs = db.query(Organization).filter(Organization.github_installation_id == installation_id).all()
            for org in orgs:
                org.github_installation_id = None
            db.commit()
            return {"status": "installation_removed", "installation_id": installation_id}

    return {"status": "ignored", "event": event, "action": action}


@router.post("/repos/map", status_code=status.HTTP_201_CREATED)
async def map_domain_to_repo(
    mapping: RepoMappingCreate,
    auth: AuthenticatedContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Maps a verified domain to a GitHub repository for automated PR creation."""
    existing = db.query(DomainRepoMapping).filter(
        DomainRepoMapping.org_id == auth.org_id,
        DomainRepoMapping.domain == mapping.domain.strip().lower()
    ).first()

    if existing:
        existing.repo_full_name = mapping.repo_full_name.strip()
        existing.default_branch = mapping.default_branch.strip()
        db.commit()
        db.refresh(existing)
        return {"status": "updated", "id": existing.id, "domain": existing.domain, "repo": existing.repo_full_name}

    import uuid
    new_map = DomainRepoMapping(
        id=f"map_{uuid.uuid4().hex[:12]}",
        org_id=auth.org_id,
        domain=mapping.domain.strip().lower(),
        repo_full_name=mapping.repo_full_name.strip(),
        default_branch=mapping.default_branch.strip(),
    )
    db.add(new_map)
    db.commit()
    db.refresh(new_map)
    return {"status": "created", "id": new_map.id, "domain": new_map.domain, "repo": new_map.repo_full_name}
