import pytest
import httpx
from test_target.vulnerable_app import mock_app
from backend.main import app
from backend.models import ScanRequest, VerificationCheckRequest, VerificationMethod

@pytest.mark.asyncio
async def test_full_pipeline_against_vulnerable_target():
    # Run against mock app in ASGI in-memory mode or test endpoints
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Health check
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

        # 2. Start Scan
        scan_req = {
            "url": "http://127.0.0.1:9000",
            "scan_type": "passive",
            "framework_hint": "nginx"
        }
        start_resp = await client.post("/api/scan/start", json=scan_req)
        assert start_resp.status_code == 200
        scan_id = start_resp.json()["scan_id"]
        assert scan_id.startswith("scan_")

        # 3. Domain Verification generation
        verify_resp = await client.post("/api/verify/generate?domain=127.0.0.1")
        assert verify_resp.status_code == 200
        challenge = verify_resp.json()
        assert challenge["domain"] == "127.0.0.1"
        assert challenge["http_file_path"] == "/.well-known/security-check.txt"

        # 4. Domain Status check (localhost is pre-whitelisted for local testing)
        status_resp = await client.get("/api/verify/status?domain=127.0.0.1")
        assert status_resp.status_code == 200
        assert status_resp.json()["verified"] is True


@pytest.mark.asyncio
async def test_audit_vulnerable_app_direct():
    from backend.scanners.active_dast import ActiveDASTScanner
    from backend.scanners.secrets_scanner import SecretsScanner
    from backend.scanners.passive_recon import PassiveReconScanner
    from backend.scanners.sensitive_files import SensitiveFilesScanner

    transport = httpx.ASGITransport(app=mock_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testtarget") as client:
        # 1. Test XSS Canary Reflection on /search
        active_scanner = ActiveDASTScanner()
        xss_findings = await active_scanner._audit_xss_reflection(client, "http://testtarget/search")
        assert len(xss_findings) >= 1
        assert any(f.cwe_id == "CWE-79" for f in xss_findings)

        # 2. Test SQLi Boundary on /api/products
        sqli_findings = await active_scanner._audit_sqli_boundaries(client, "http://testtarget/api/products")
        assert len(sqli_findings) >= 1
        assert any(f.cwe_id == "CWE-89" for f in sqli_findings)

        # 3. Test Open Redirect on /login
        redirect_findings = await active_scanner._audit_open_redirect(client, "http://testtarget/login")
        assert len(redirect_findings) >= 1
        assert any(f.cwe_id == "CWE-601" for f in redirect_findings)

        # 4. Test Secrets Scanner on bundle.js
        secrets_scanner = SecretsScanner()
        resp = await client.get("http://testtarget/static/bundle.js")
        secret_findings = secrets_scanner._analyze_content(resp.text, "http://testtarget/static/bundle.js")
        assert len(secret_findings) >= 1
        assert any(f.cwe_id == "CWE-798" for f in secret_findings)
