import os
import pytest
import httpx
from datetime import datetime

from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import Organization, ApiKey, User, Scan, FindingDB
from backend.db.repository import save_or_update_scan, get_scan
from backend.models import ScanResult, Finding, ScanStatus, SeverityLevel
from backend.auth.security import generate_api_key, hash_api_key, create_access_token, decode_access_token


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_db_scan_and_finding_persistence():
    db = SessionLocal()
    try:
        scan_id = "test_persist_001"
        result = ScanResult(
            scan_id=scan_id,
            target_url="https://audit.local",
            domain="audit.local",
            status=ScanStatus.COMPLETED,
            started_at="2026-09-26T12:00:00Z",
            score=85,
            grade="B+",
            findings=[
                Finding(
                    id="TEST-FINDING-01",
                    name="Missing Header",
                    category="Security Headers",
                    severity=SeverityLevel.HIGH,
                    endpoint="https://audit.local/login",
                    description="Missing CSP header",
                    cwe_id="CWE-693",
                )
            ]
        )

        saved = save_or_update_scan(db, result, org_id="default-org")
        assert saved.scan_id == scan_id
        assert saved.score == 85

        fetched = get_scan(db, scan_id)
        assert fetched is not None
        assert fetched.scan_id == scan_id
        assert len(fetched.findings) == 1
        assert fetched.findings[0].cwe_id == "CWE-693"
    finally:
        db.close()


def test_jwt_token_creation_and_decoding():
    payload = {"sub": "user_123", "org_id": "org_456", "role": "admin"}
    token = create_access_token(payload)
    assert token is not None

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "user_123"
    assert decoded["org_id"] == "org_456"
    assert decoded["role"] == "admin"


@pytest.mark.asyncio
async def test_api_key_generation_and_rbac():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Create Organization
        org_payload = {"name": "Acme Corp", "id": "acme_test_org"}
        create_org_resp = await client.post("/api/auth/organizations", json=org_payload)
        assert create_org_resp.status_code in (201, 400)

        # 2. Create Admin API Key directly in DB
        db = SessionLocal()
        raw_key, key_hash = generate_api_key()
        try:
            admin_key = ApiKey(
                id="key_admin_test",
                org_id="acme_test_org",
                key_hash=key_hash,
                name="Admin Test Key",
                role="admin",
                is_active=True,
            )
            db.merge(admin_key)
            db.commit()
        finally:
            db.close()

        # 3. Call endpoint with Admin API key -> Success
        headers = {"X-API-Key": raw_key}
        list_keys_resp = await client.get("/api/auth/api-keys", headers=headers)
        assert list_keys_resp.status_code == 200
        keys_data = list_keys_resp.json()
        assert any(k["id"] == "key_admin_test" for k in keys_data)

        # 4. Create Viewer API Key
        raw_viewer_key, viewer_hash = generate_api_key()
        db = SessionLocal()
        try:
            viewer_key = ApiKey(
                id="key_viewer_test",
                org_id="acme_test_org",
                key_hash=viewer_hash,
                name="Viewer Test Key",
                role="viewer",
                is_active=True,
            )
            db.merge(viewer_key)
            db.commit()
        finally:
            db.close()

        # 5. Viewer attempts to create another API Key -> 403 Forbidden
        viewer_headers = {"X-API-Key": raw_viewer_key}
        forbidden_resp = await client.post(
            "/api/auth/api-keys",
            json={"name": "Illegal Key", "role": "member"},
            headers=viewer_headers,
        )
        assert forbidden_resp.status_code == 403
        assert "Forbidden" in forbidden_resp.json()["detail"]


@pytest.mark.asyncio
async def test_strict_auth_enforcement_when_enabled():
    os.environ["SECOPS_REQUIRE_AUTH"] = "true"
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.post("/api/scan/start", json={"url": "https://example.com"})
            assert resp.status_code == 401
            assert "Authentication required" in resp.json()["detail"]
    finally:
        os.environ["SECOPS_REQUIRE_AUTH"] = "false"
