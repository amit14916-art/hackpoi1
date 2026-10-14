import os
import json
import pytest
import httpx
from unittest.mock import patch, AsyncMock

from backend.main import app
from backend.db.session import init_db, SessionLocal
from backend.db.models import WebhookEndpoint, Organization
from backend.models import Finding, SeverityLevel
from backend.integrations.cicd import diff_findings, verify_webhook_token
from backend.notifications.dispatcher import NotificationDispatcher
from backend.notifications.slack import SlackNotificationProvider


@pytest.fixture(autouse=True)
def setup_database():
    init_db()


def test_finding_diffing_new_and_resolved():
    f1 = Finding(
        id="FINDING-A",
        name="SQLi in /login",
        category="Injection",
        severity=SeverityLevel.CRITICAL,
        cwe_id="CWE-89",
        endpoint="https://app.local/login",
        description="SQLi",
    )
    f2 = Finding(
        id="FINDING-B",
        name="XSS in /search",
        category="XSS",
        severity=SeverityLevel.HIGH,
        cwe_id="CWE-79",
        endpoint="https://app.local/search",
        description="XSS",
    )
    f3 = Finding(
        id="FINDING-C",
        name="Missing HSTS",
        category="Security Headers",
        severity=SeverityLevel.LOW,
        cwe_id="CWE-693",
        endpoint="https://app.local/",
        description="Missing HSTS",
    )

    previous_findings = [f1, f2]
    # In current scan, f1 is resolved, f2 remains, and f3 is newly detected
    current_findings = [f2, f3]

    new_findings, resolved_findings = diff_findings(current_findings, previous_findings)

    assert len(new_findings) == 1
    assert new_findings[0].id == "FINDING-C"
    assert len(resolved_findings) == 1
    assert resolved_findings[0].id == "FINDING-A"


def test_webhook_token_verification_providers():
    secret = "secret_tok_123"

    # 1. Generic webhook header
    assert verify_webhook_token("generic", secret, b"{}", {"x-webhook-secret": secret}) is True
    assert verify_webhook_token("generic", secret, b"{}", {"x-webhook-secret": "wrong"}) is False

    # 2. GitLab CI header
    assert verify_webhook_token("gitlab_ci", secret, b"{}", {"x-gitlab-token": secret}) is True

    # 3. GitHub Actions Bearer
    assert verify_webhook_token("github_actions", secret, b"{}", {"authorization": f"Bearer {secret}"}) is True


@pytest.mark.asyncio
async def test_cicd_webhook_deploy_scan_trigger():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Register Webhook Endpoint
        ep_create = await client.post(
            "/api/integrations/cicd/endpoints",
            json={
                "provider": "generic",
                "target_domain": "deployed-service.local",
                "secret_token": "deploy_secret_abc123",
            }
        )
        assert ep_create.status_code == 201

        # 2. Trigger Deploy Webhook with correct token -> 202 Accepted
        trigger_resp = await client.post(
            "/api/webhooks/deploy/default-org",
            headers={"X-Webhook-Secret": "deploy_secret_abc123"},
            json={"target_domain": "deployed-service.local", "scan_type": "passive"}
        )
        assert trigger_resp.status_code == 202
        data = trigger_resp.json()
        assert data["status"] == "scan_triggered"
        assert data["scan_id"].startswith("scan_")

        # 3. Trigger Deploy Webhook with invalid token -> 401 Unauthorized
        bad_resp = await client.post(
            "/api/webhooks/deploy/default-org",
            headers={"X-Webhook-Secret": "wrong_token"},
            json={"target_domain": "deployed-service.local"}
        )
        assert bad_resp.status_code == 401


@pytest.mark.asyncio
async def test_notification_dispatcher_severity_threshold():
    dispatcher = NotificationDispatcher()

    # CRITICAL should trigger for HIGH threshold
    assert dispatcher.is_severity_sufficient("CRITICAL", "HIGH") is True
    assert dispatcher.is_severity_sufficient("HIGH", "HIGH") is True

    # LOW should NOT trigger for HIGH threshold
    assert dispatcher.is_severity_sufficient("LOW", "HIGH") is False
    assert dispatcher.is_severity_sufficient("INFO", "HIGH") is False


@pytest.mark.asyncio
async def test_slack_notification_block_payload():
    provider = SlackNotificationProvider()
    db = SessionLocal()
    try:
        org = db.query(Organization).filter(Organization.id == "default-org").first()
        org.slack_webhook_url = "https://hooks.slack.com/services/T00/B00/X00"
        db.commit()
    finally:
        db.close()

    with patch("httpx.AsyncClient.post", new=AsyncMock()) as mock_post:
        mock_post.return_value = httpx.Response(200, text="ok")
        sent = await provider.send(
            org_id="default-org",
            message="Test Alert",
            severity="CRITICAL",
            details={
                "domain": "acme.com",
                "scan_id": "scan_123",
                "new_findings_count": 2,
                "top_findings": [{"name": "SQLi", "severity": "CRITICAL", "cwe_id": "CWE-89"}],
            }
        )
        assert sent is True
        assert mock_post.called
        call_json = mock_post.call_args[1]["json"]
        assert "blocks" in call_json
        assert "🚨" in call_json["text"]
