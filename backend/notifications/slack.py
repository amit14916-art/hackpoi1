import logging
from typing import Optional, Dict, Any
import httpx

from backend.notifications.base import BaseNotificationProvider
from backend.db.session import SessionLocal
from backend.db.models import Organization

logger = logging.getLogger("secops.notifications.slack")


class SlackNotificationProvider(BaseNotificationProvider):
    async def send(
        self,
        org_id: str,
        message: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Sends a Block Kit formatted alert to the organization's Slack incoming webhook."""
        webhook_url = None
        db = SessionLocal()
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            if org and org.slack_webhook_url:
                webhook_url = org.slack_webhook_url
        finally:
            db.close()

        if not webhook_url:
            logger.info(f"No Slack webhook configured for organization {org_id}. Skipping Slack notification.")
            return False

        details = details or {}
        domain = details.get("domain", "Unknown Domain")
        scan_id = details.get("scan_id", "")
        new_count = details.get("new_findings_count", 0)
        resolved_count = details.get("resolved_findings_count", 0)
        top_findings = details.get("top_findings", [])

        # Construct Slack Block Kit payload
        sev_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "🟡",
            "LOW": "ℹ️",
            "INFO": "💬",
        }.get(severity.upper(), "🛡️")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{sev_emoji} SecOps Guardian Alert: {severity.upper()} Vulnerabilities Detected",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target Domain:*\n`{domain}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n`{severity.upper()}`"},
                    {"type": "mrkdwn", "text": f"*New Findings:*\n`{new_count}`"},
                    {"type": "mrkdwn", "text": f"*Resolved Findings:*\n`{resolved_count}`"},
                ],
            },
        ]

        if top_findings:
            finding_texts = []
            for f in top_findings[:5]:
                finding_texts.append(f"• *[{f.get('severity', 'INFO')}]* {f.get('name', 'Issue')} (`{f.get('cwe_id', 'N/A')}`)")
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top Findings:*\n" + "\n".join(finding_texts),
                },
            })

        if scan_id:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Scan ID: `{scan_id}` | Automated CI/CD Continuous Scanning Engine"}
                ],
            })

        payload = {
            "text": f"{sev_emoji} [{severity}] Security Findings Detected on {domain}: {message}",
            "blocks": blocks,
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(webhook_url, json=payload)
                if resp.status_code == 200:
                    logger.info(f"Slack notification sent successfully for org {org_id}")
                    return True
                else:
                    logger.error(f"Slack webhook error {resp.status_code}: {resp.text}")
                    return False
        except Exception as e:
            logger.error(f"Failed to deliver Slack notification: {str(e)}")
            return False
