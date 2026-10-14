import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Any, List

from backend.notifications.base import BaseNotificationProvider
from backend.db.session import SessionLocal
from backend.db.models import Organization, User

logger = logging.getLogger("secops.notifications.email")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM", "alerts@secopsguardian.io")


class EmailNotificationProvider(BaseNotificationProvider):
    async def send(
        self,
        org_id: str,
        message: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Sends an HTML email notification via SMTP to the organization admins."""
        if not SMTP_HOST:
            logger.info("SMTP_HOST not configured. Email notifications skipped.")
            return False

        details = details or {}
        domain = details.get("domain", "Unknown Domain")
        scan_id = details.get("scan_id", "")
        new_count = details.get("new_findings_count", 0)

        # Retrieve recipients: admin users of this organization
        recipients: List[str] = []
        db = SessionLocal()
        try:
            users = db.query(User).filter(User.org_id == org_id).all()
            recipients = [u.email for u in users if u.email]
        finally:
            db.close()

        if not recipients:
            logger.info(f"No user emails found for org {org_id}. Skipping email alert.")
            return False

        subject = f"🛡️ SecOps Guardian Alert: {severity.upper()} Findings on {domain}"

        html_body = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1e293b; background: #f8fafc; padding: 24px;">
            <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; padding: 28px;">
                <h2 style="color: #0f172a; margin-top: 0;">🛡️ SecOps Guardian Continuous Scan Alert</h2>
                <p style="font-size: 15px; line-height: 1.5;">A recent deployment scan detected new security vulnerabilities matching your notification threshold.</p>
                <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
                    <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">Domain:</td><td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{domain}</td></tr>
                    <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">Severity:</td><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; color: #dc2626; font-weight: bold;">{severity.upper()}</td></tr>
                    <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">New Findings:</td><td style="padding: 8px; border-bottom: 1px solid #e2e8f0;">{new_count}</td></tr>
                    <tr><td style="padding: 8px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">Scan ID:</td><td style="padding: 8px; border-bottom: 1px solid #e2e8f0;"><code>{scan_id}</code></td></tr>
                </table>
                <p style="color: #64748b; font-size: 13px;">Review the full interactive audit results in your SecOps Guardian console.</p>
            </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(message, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.starttls()
                if SMTP_USER and SMTP_PASSWORD:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_FROM, recipients, msg.as_string())
            logger.info(f"Email alert sent to {recipients} for org {org_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")
            return False
