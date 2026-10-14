import os
import pytest
import httpx
from datetime import datetime

from backend.main import app
from backend.db.session import init_db, SessionLocal
from backend.db.models import Organization, User
from backend.auth.security import encrypt_secret, decrypt_secret, decode_access_token


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_fernet_secret_encryption_and_decryption():
    plain = "azure-client-secret-xyz-987"
    encrypted = encrypt_secret(plain)
    assert encrypted != plain
    assert len(encrypted) > 20

    decrypted = decrypt_secret(encrypted)
    assert decrypted == plain


@pytest.mark.asyncio
async def test_saml_sp_metadata_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.get("/api/auth/saml/default-org/metadata")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/xml"
        xml = resp.text
        assert "EntityDescriptor" in xml
        assert "AssertionConsumerService" in xml
        assert "/api/auth/sso/default-org/callback" in xml


@pytest.mark.asyncio
async def test_sso_config_and_login_redirect():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Configure Google OAuth SSO
        config_resp = await client.post(
            "/api/auth/sso/default-org/config",
            json={
                "sso_provider": "google",
                "client_id": "google-client-id-12345.apps.googleusercontent.com",
                "client_secret": "my-google-secret-abc",
            }
        )
        assert config_resp.status_code == 200
        assert config_resp.json()["provider"] == "google"

        # 2. Initiate login -> redirects to Google
        login_resp = await client.get("/api/auth/sso/default-org/login", follow_redirects=False)
        assert login_resp.status_code in (302, 307)
        target = login_resp.headers["location"]
        assert "accounts.google.com" in target
        assert "client_id=google-client-id-12345" in target


@pytest.mark.asyncio
async def test_sso_auto_provisioning_and_jwt_issuance():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Simulate SSO callback with mock user credentials
        sso_resp = await client.get(
            "/api/auth/sso/default-org/callback?mock_email=alice_sso@acme.com&mock_name=Alice+Smith"
        )
        assert sso_resp.status_code == 200
        data = sso_resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["email"] == "alice_sso@acme.com"
        assert data["user"]["role"] == "member"

        # Verify token validity
        token = data["access_token"]
        payload = decode_access_token(token)
        assert payload["email"] == "alice_sso@acme.com"
        assert payload["org_id"] == "default-org"

        # Verify user can access authenticated API using this JWT token
        auth_headers = {"Authorization": f"Bearer {token}"}
        status_resp = await client.get("/api/verify/status?domain=example.com", headers=auth_headers)
        assert status_resp.status_code == 200
