import os
import datetime
from typing import Optional
from dataclasses import dataclass
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import Organization, ApiKey, User
from backend.auth.security import hash_api_key, decode_access_token

ROLE_HIERARCHY = {
    "admin": 3,
    "member": 2,
    "viewer": 1,
}

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthenticatedContext:
    org_id: str
    user_id: Optional[str]
    role: str
    auth_method: str  # "api_key", "jwt", "dev_fallback"

    def has_role(self, required_role: str) -> bool:
        current_level = ROLE_HIERARCHY.get(self.role.lower(), 0)
        required_level = ROLE_HIERARCHY.get(required_role.lower(), 0)
        return current_level >= required_level


def _get_or_create_default_org(db: Session) -> Organization:
    """Auto-provisions a default test/dev organization when running in dev/test mode."""
    org = db.query(Organization).filter(Organization.id == "default-org").first()
    if not org:
        org = Organization(
            id="default-org",
            name="Default Organization",
            created_at=datetime.datetime.utcnow(),
        )
        db.add(org)
        db.commit()
        db.refresh(org)
    return org


async def get_current_auth(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedContext:
    """
    FastAPI dependency that enforces authentication via API key or JWT token.
    Supports:
      1. X-API-Key header (raw key)
      2. Authorization: Bearer <raw_api_key or jwt_token>
      3. Fallback to default org if SECOPS_REQUIRE_AUTH is not explicitly 'true'
    """
    api_key_header = request.headers.get("X-API-Key")
    token_candidate: Optional[str] = None

    if api_key_header:
        token_candidate = api_key_header.strip()
    elif bearer and bearer.credentials:
        token_candidate = bearer.credentials.strip()

    # 1. If a token was provided
    if token_candidate:
        # Check if it is an API Key (starts with secops_ or contains no JWT dots)
        if token_candidate.startswith("secops_") or token_candidate.count(".") != 2:
            key_hash = hash_api_key(token_candidate)
            api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash, ApiKey.is_active == True).first()
            if not api_key:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or revoked API key.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            # Update last used timestamp
            api_key.last_used_at = datetime.datetime.utcnow()
            db.commit()

            return AuthenticatedContext(
                org_id=api_key.org_id,
                user_id=api_key.user_id,
                role=api_key.role,
                auth_method="api_key",
            )
        else:
            # Attempt to decode as JWT session token
            payload = decode_access_token(token_candidate)
            if not payload or "org_id" not in payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired session token.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return AuthenticatedContext(
                org_id=payload["org_id"],
                user_id=payload.get("sub"),
                role=payload.get("role", "member"),
                auth_method="jwt",
            )

    # 2. No token provided: check if strict auth is enforced
    strict_auth = os.getenv("SECOPS_REQUIRE_AUTH", "false").lower() in ("true", "1", "yes")
    if strict_auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide X-API-Key or Authorization: Bearer <token>.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Dev / Test fallback mode
    default_org = _get_or_create_default_org(db)
    return AuthenticatedContext(
        org_id=default_org.id,
        user_id=None,
        role="admin",
        auth_method="dev_fallback",
    )


def require_role(min_role: str):
    """Dependency factory checking that the authenticated caller has at least min_role."""
    def role_checker(auth: AuthenticatedContext = Depends(get_current_auth)) -> AuthenticatedContext:
        if not auth.has_role(min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Action requires '{min_role}' role or higher. Current role: '{auth.role}'.",
            )
        return auth
    return role_checker
