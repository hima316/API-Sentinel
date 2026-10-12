"""Detection rule for high-frequency request bursts (flooding / scraping / DoS)."""

from datetime import datetime, timedelta
from typing import List, Optional

from app.core.config import settings
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.log import RequestLog
from app.rules.base import BaseRule


class RequestBurstRule(BaseRule):
    """Flags a client that sends more than a threshold number of requests in a short time window."""

    rule_name: str = "Request Burst"
    severity: AlertSeverity = AlertSeverity.MEDIUM

    def __init__(
        self,
        threshold: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> None:
        """Initialize rule with configurable request threshold and time window."""
        self.threshold: int = (
            threshold if threshold is not None else settings.BURST_REQUEST_THRESHOLD
        )
        self.window_seconds: int = (
            window_seconds
            if window_seconds is not None
            else settings.BURST_WINDOW_SECONDS
        )

    def evaluate(
        self,
        client_id: str,
        logs: List[RequestLog],
        current_time: datetime,
    ) -> Optional[Alert]:
        """Check if total request volume within time window meets or exceeds threshold."""
        cutoff = current_time - timedelta(seconds=self.window_seconds)

        recent_requests = [log for log in logs if log.timestamp >= cutoff]

        if len(recent_requests) >= self.threshold:
            return Alert(
                timestamp=current_time,
                client_id=client_id,
                rule_name=self.rule_name,
                severity=self.severity,
                reason=(
                    f"Client '{client_id}' sent {len(recent_requests)} requests "
                    f"reaching the burst threshold of {self.threshold} within {self.window_seconds}s."
                ),
                evidence={
                    "request_count": len(recent_requests),
                    "threshold": self.threshold,
                    "window_seconds": self.window_seconds,
                },
                status=AlertStatus.OPEN,
            )

        return None
