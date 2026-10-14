import datetime
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    Text,
    DateTime,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import relationship

from backend.db.session import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    # Feature 1: GitHub App Integration
    github_installation_id = Column(String(64), nullable=True)

    # Feature 2: Notifications
    slack_webhook_url = Column(String(512), nullable=True)
    notify_on_new_findings = Column(Boolean, default=True)
    min_severity_to_notify = Column(String(16), default="HIGH")

    # Feature 5: SSO
    saml_metadata = Column(Text, nullable=True)
    sso_provider = Column(String(32), nullable=True)  # "google", "microsoft", "saml"
    sso_client_id = Column(String(255), nullable=True)
    sso_client_secret_encrypted = Column(Text, nullable=True)
    sso_discovery_url = Column(String(512), nullable=True)

    # Relationships
    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="organization", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="organization", cascade="all, delete-orphan")
    domains = relationship("Domain", back_populates="organization", cascade="all, delete-orphan")
    webhook_endpoints = relationship("WebhookEndpoint", back_populates="organization", cascade="all, delete-orphan")
    repo_mappings = relationship("DomainRepoMapping", back_populates="organization", cascade="all, delete-orphan")


class User(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    role = Column(String(16), default="member")  # "admin", "member", "viewer"
    hashed_password = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="users")
    api_keys = relationship("ApiKey", back_populates="user")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(String(64), primary_key=True, index=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    key_hash = Column(String(128), nullable=False, index=True)
    name = Column(String(255), nullable=False, default="Default API Key")
    role = Column(String(16), default="member")  # "admin", "member", "viewer"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="api_keys")
    user = relationship("User", back_populates="api_keys")


class Scan(Base):
    __tablename__ = "scans"

    scan_id = Column(String(64), primary_key=True, index=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    target_url = Column(String(1024), nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    status = Column(String(32), default="QUEUED", index=True)
    current_step = Column(String(255), default="Initializing")
    progress = Column(Integer, default=0)
    started_at = Column(String(64), nullable=False)
    completed_at = Column(String(64), nullable=True)
    score = Column(Integer, default=100)
    grade = Column(String(8), default="A+")
    findings_summary = Column(JSON, default=dict)
    ai_summary = Column(Text, nullable=True)
    executive_overview = Column(Text, nullable=True)
    is_domain_verified = Column(Boolean, default=False)
    error = Column(Text, nullable=True)
    scan_type = Column(String(32), default="passive")
    framework_hint = Column(String(64), nullable=True)
    repo_full_name = Column(String(255), nullable=True)

    organization = relationship("Organization", back_populates="scans")
    findings = relationship("FindingDB", back_populates="scan", cascade="all, delete-orphan")


class FindingDB(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True, index=True)
    finding_id = Column(String(128), nullable=False, index=True)  # e.g., "ACTIVE-SQLI-TEST"
    scan_id = Column(String(64), ForeignKey("scans.scan_id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    category = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False, index=True)  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(128), nullable=True)
    cwe_id = Column(String(32), nullable=True, index=True)
    owasp_category = Column(String(128), nullable=True)
    confidence = Column(String(32), default="CERTAIN")
    endpoint = Column(String(1024), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, nullable=True)
    request_proof = Column(Text, nullable=True)
    response_proof = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation_summary = Column(Text, nullable=True)
    remediation_effort = Column(String(16), default="LOW")
    remediation_code = Column(JSON, default=dict)
    references_list = Column(JSON, default=list)

    # Feature 1: GitHub PR Auto-Remediation tracking
    pr_url = Column(String(512), nullable=True)
    pr_status = Column(String(32), nullable=True)  # "open", "merged", "closed"
    pr_branch = Column(String(128), nullable=True)

    scan = relationship("Scan", back_populates="findings")


class DomainRepoMapping(Base):
    __tablename__ = "domain_repo_mappings"

    id = Column(String(64), primary_key=True, index=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    repo_full_name = Column(String(255), nullable=False)  # e.g. "octocat/hello-world"
    default_branch = Column(String(64), default="main")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="repo_mappings")


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"

    id = Column(String(64), primary_key=True, index=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    secret_token = Column(String(128), nullable=False)
    provider = Column(String(32), default="generic")  # "generic", "github_actions", "gitlab_ci"
    target_domain = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="webhook_endpoints")


class Domain(Base):
    __tablename__ = "domains"

    id = Column(String(64), primary_key=True, index=True)
    org_id = Column(String(64), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    url = Column(String(1024), nullable=False)
    domain_name = Column(String(255), nullable=False, index=True)
    is_domain_verified = Column(Boolean, default=False)
    last_scan_id = Column(String(64), ForeignKey("scans.scan_id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="domains")
    last_scan = relationship("Scan", foreign_keys=[last_scan_id])
