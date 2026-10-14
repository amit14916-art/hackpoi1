import uuid
import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import Organization, ApiKey, User
from backend.auth.schemas import (
    OrganizationCreate,
    OrganizationResponse,
    UserCreate,
    UserResponse,
    ApiKeyCreate,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
)
from backend.auth.security import generate_api_key
from backend.auth.dependencies import get_current_auth, require_role, AuthenticatedContext

router = APIRouter(prefix="/api/auth", tags=["Authentication & Organizations"])


@router.post("/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
async def create_organization(data: OrganizationCreate, db: Session = Depends(get_db)):
    org_id = data.id or f"org_{uuid.uuid4().hex[:12]}"
    existing = db.query(Organization).filter(Organization.id == org_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Organization ID already exists.")

    org = Organization(
        id=org_id,
        name=data.name,
        created_at=datetime.datetime.utcnow(),
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@router.get("/organizations/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: str,
    auth: AuthenticatedContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    if auth.org_id != org_id and not auth.has_role("admin"):
        raise HTTPException(status_code=403, detail="Cannot access other organizations.")

    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")
    return org


@router.post("/api-keys", response_model=ApiKeyCreatedResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: ApiKeyCreate,
    auth: AuthenticatedContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    raw_key, key_hash = generate_api_key()
    key_id = f"key_{uuid.uuid4().hex[:12]}"

    api_key = ApiKey(
        id=key_id,
        org_id=auth.org_id,
        user_id=data.user_id,
        key_hash=key_hash,
        name=data.name,
        role=data.role,
        is_active=True,
        created_at=datetime.datetime.utcnow(),
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return ApiKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        role=api_key.role,
        raw_api_key=raw_key,
        org_id=api_key.org_id,
        created_at=api_key.created_at,
    )


@router.get("/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(
    auth: AuthenticatedContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    keys = db.query(ApiKey).filter(ApiKey.org_id == auth.org_id).all()
    return keys


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_200_OK)
async def revoke_api_key(
    key_id: str,
    auth: AuthenticatedContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    key = db.query(ApiKey).filter(ApiKey.id == key_id, ApiKey.org_id == auth.org_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found.")
    key.is_active = False
    db.commit()
    return {"message": "API key revoked successfully.", "key_id": key_id}


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreate,
    auth: AuthenticatedContext = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter(User.org_id == auth.org_id, User.email == data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists in organization.")

    user = User(
        id=f"user_{uuid.uuid4().hex[:12]}",
        org_id=auth.org_id,
        email=data.email,
        full_name=data.full_name,
        role=data.role,
        created_at=datetime.datetime.utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    auth: AuthenticatedContext = Depends(require_role("member")),
    db: Session = Depends(get_db),
):
    users = db.query(User).filter(User.org_id == auth.org_id).all()
    return users
