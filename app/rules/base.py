"""Base interfaces for security abuse detection rules."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import List, Optional

from app.models.alert import Alert, AlertSeverity
from app.models.log import RequestLog


class BaseRule(ABC):
    """Abstract base class for all rule-based detection evaluators."""

    rule_name: str
    severity: AlertSeverity

    @abstractmethod
    def evaluate(
        self,
        client_id: str,
        logs: List[RequestLog],
        current_time: datetime,
    ) -> Optional[Alert]:
        """Evaluate recent request logs for a specific client.

        Args:
            client_id: Identifier of the client being evaluated.
            logs: List of recent RequestLog instances for this client.
            current_time: Current UTC timestamp representing evaluation time.

        Returns:
            An Alert instance if abuse is detected, otherwise None.
        """
        pass
