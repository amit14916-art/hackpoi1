from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    id: Optional[str] = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    created_at: datetime
    github_installation_id: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    notify_on_new_findings: bool = True
    min_severity_to_notify: str = "HIGH"
    sso_provider: Optional[str] = None

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    email: str = Field(..., min_length=3, max_length=255, description="User email address")
    full_name: Optional[str] = None
    role: str = Field("member", pattern="^(admin|member|viewer)$")
    password: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    org_id: str
    email: str
    full_name: Optional[str] = None
    role: str
    created_at: datetime

    class Config:
        from_attributes = True


class ApiKeyCreate(BaseModel):
    name: str = Field("Default Key", min_length=1, max_length=255)
    role: str = Field("member", pattern="^(admin|member|viewer)$")
    user_id: Optional[str] = None


class ApiKeyCreatedResponse(BaseModel):
    id: str
    name: str
    role: str
    raw_api_key: str
    org_id: str
    created_at: datetime


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    role: str
    org_id: str
    user_id: Optional[str] = None
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_hours: int = 24
    user: Optional[UserResponse] = None
