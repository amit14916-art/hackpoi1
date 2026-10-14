from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class BaseNotificationProvider(ABC):
    @abstractmethod
    async def send(
        self,
        org_id: str,
        message: str,
        severity: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Sends a notification to the configured provider."""
        pass
