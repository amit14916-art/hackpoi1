import os
import hmac
import hashlib
import json
import pytest
import httpx
from unittest.mock import patch, AsyncMock

from backend.main import app
from backend.db.session import init_db
from backend.models import Finding, SeverityLevel
from backend.integrations.github_app import GitHubAppService


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_github_patch_file_path_heuristics():
    finding = Finding(
        id="SEC-HEADER-CSP",
        name="Missing Content-Security-Policy",
        category="Security Headers",
        severity=SeverityLevel.MEDIUM,
        endpoint="https://target.local/",
        description="Missing CSP",
    )

    # Nginx framework hint
    nginx_path = GitHubAppService.infer_patch_file_path(finding, framework_hint="nginx")
    assert nginx_path == "nginx.conf"

    # Apache framework hint
    apache_path = GitHubAppService.infer_patch_file_path(finding, framework_hint="apache")
    assert apache_path == ".htaccess"

    # Django framework hint
    django_path = GitHubAppService.infer_patch_file_path(finding, framework_hint="django")
    assert django_path == "settings.py"

    # Default category heuristic for headers
    default_path = GitHubAppService.infer_patch_file_path(finding, framework_hint=None)
    assert default_path == "security_headers.conf"


def test_github_webhook_signature_verification():
    secret = "my_test_github_secret"
    os.environ["GITHUB_WEBHOOK_SECRET"] = secret

    payload = b'{"action": "created", "installation": {"id": 12345}}'
    expected_sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    # Valid signature
    assert GitHubAppService.verify_webhook_signature(payload, expected_sig) is True

    # Tampered signature
    assert GitHubAppService.verify_webhook_signature(payload, "sha256=invalid") is False


@pytest.mark.asyncio
async def test_github_connect_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post("/api/integrations/github/connect")
        assert resp.status_code == 200
        data = resp.json()
        assert "install_url" in data
        assert "github.com/apps" in data["install_url"]


@pytest.mark.asyncio
async def test_domain_repo_mapping():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        resp = await client.post(
            "/api/integrations/github/repos/map",
            json={
                "domain": "secops-test.com",
                "repo_full_name": "acme/web-app",
                "default_branch": "main",
            }
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["domain"] == "secops-test.com"
        assert data["repo"] == "acme/web-app"


@pytest.mark.asyncio
async def test_auto_pr_creation_flow_mocked():
    finding = Finding(
        id="ACTIVE-SQLI-TEST",
        name="SQL Injection in id param",
        category="Injection",
        severity=SeverityLevel.CRITICAL,
        cwe_id="CWE-89",
        endpoint="https://target.local/api/user?id=1",
        description="SQL syntax error leak",
        remediation_code={"python": "cursor.execute('SELECT * FROM users WHERE id = %s', (id,))"},
    )

    with patch.object(GitHubAppService, "get_installation_token", new=AsyncMock(return_value="mock_token")):
        with patch("httpx.AsyncClient.get") as mock_get, patch("httpx.AsyncClient.post") as mock_post, patch("httpx.AsyncClient.put") as mock_put:
            # Mock get default branch ref
            mock_get.return_value = httpx.Response(200, json={"object": {"sha": "base123sha"}})
            # Mock create branch ref
            mock_post.side_effect = [
                httpx.Response(201, json={"ref": "refs/heads/secops-fix/active-sqli-test"}),
                httpx.Response(201, json={"html_url": "https://github.com/acme/repo/pull/42", "number": 42}),
            ]
            # Mock put content
            mock_put.return_value = httpx.Response(201, json={"content": {"sha": "filesha"}})

            pr_res = await GitHubAppService.create_branch_and_pr(
                installation_id="inst_123",
                repo_full_name="acme/repo",
                finding=finding,
                default_branch="main",
                framework_hint="python",
            )

            assert pr_res is not None
            assert pr_res["pr_url"] == "https://github.com/acme/repo/pull/42"
            assert pr_res["pr_status"] == "open"
            assert pr_res["pr_branch"] == "secops-fix/active-sqli-test"
