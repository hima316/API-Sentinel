"""Detection rule for repeated failed login attempts (brute force / credential stuffing)."""

from datetime import datetime, timedelta
from typing import List, Optional

from app.core.config import settings
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.log import RequestLog
from app.rules.base import BaseRule


class RepeatedFailedLoginsRule(BaseRule):
    """Flags a client that reaches a threshold of failed login attempts within a time window."""

    rule_name: str = "Repeated Failed Logins"
    severity: AlertSeverity = AlertSeverity.HIGH

    def __init__(
        self,
        threshold: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> None:
        """Initialize rule with configurable threshold and time window."""
        self.threshold: int = (
            threshold if threshold is not None else settings.FAILED_LOGIN_THRESHOLD
        )
        self.window_seconds: int = (
            window_seconds
            if window_seconds is not None
            else settings.FAILED_LOGIN_WINDOW_SECONDS
        )

    def evaluate(
        self,
        client_id: str,
        logs: List[RequestLog],
        current_time: datetime,
    ) -> Optional[Alert]:
        """Check if failed login count within time window reaches the threshold."""
        cutoff = current_time - timedelta(seconds=self.window_seconds)

        failed_attempts = [
            log
            for log in logs
            if log.timestamp >= cutoff
            and log.path == "/api/login"
            and log.method == "POST"
            and log.status_code == 401
        ]

        if len(failed_attempts) >= self.threshold:
            return Alert(
                timestamp=current_time,
                client_id=client_id,
                rule_name=self.rule_name,
                severity=self.severity,
                reason=(
                    f"Client '{client_id}' recorded {len(failed_attempts)} failed login attempts "
                    f"reaching the threshold of {self.threshold} within {self.window_seconds}s."
                ),
                evidence={
                    "failed_attempts": len(failed_attempts),
                    "threshold": self.threshold,
                    "window_seconds": self.window_seconds,
                    "target_path": "/api/login",
                },
                status=AlertStatus.OPEN,
            )

        return None
