import logging
from typing import Optional, Dict, Any, List

from backend.db.session import SessionLocal
from backend.db.models import Organization
from backend.notifications.slack import SlackNotificationProvider
from backend.notifications.email import EmailNotificationProvider

logger = logging.getLogger("secops.notifications.dispatcher")

SEVERITY_RANKS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


class NotificationDispatcher:
    def __init__(self):
        self.providers = [
            SlackNotificationProvider(),
            EmailNotificationProvider(),
        ]

    @staticmethod
    def is_severity_sufficient(finding_severity: str, threshold: str) -> bool:
        find_rank = SEVERITY_RANKS.get(finding_severity.upper(), 0)
        thresh_rank = SEVERITY_RANKS.get(threshold.upper(), 3)  # default HIGH (3)
        return find_rank >= thresh_rank

    async def dispatch(
        self,
        org_id: str,
        message: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, bool]:
        """
        Dispatches notification across all configured channels if org settings permit.
        """
        db = SessionLocal()
        notify_enabled = True
        min_sev = "HIGH"
        try:
            org = db.query(Organization).filter(Organization.id == org_id).first()
            if org:
                notify_enabled = org.notify_on_new_findings
                min_sev = org.min_severity_to_notify or "HIGH"
        finally:
            db.close()

        if not notify_enabled:
            logger.info(f"Notifications disabled for organization {org_id}.")
            return {}

        if not self.is_severity_sufficient(severity, min_sev):
            logger.info(
                f"Finding severity '{severity}' is below notification threshold '{min_sev}' for org {org_id}. Skipping."
            )
            return {}

        results = {}
        for provider in self.providers:
            prov_name = provider.__class__.__name__
            try:
                sent = await provider.send(org_id, message, severity, details)
                results[prov_name] = sent
            except Exception as e:
                logger.error(f"Provider {prov_name} error: {str(e)}")
                results[prov_name] = False

        return results
