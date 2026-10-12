"""Detection rule for endpoint probing and scanning activity (directory fuzzing / discovery)."""

from datetime import datetime, timedelta
from typing import List, Optional, Set

from app.core.config import settings
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.log import RequestLog
from app.rules.base import BaseRule


class EndpointProbingRule(BaseRule):
    """Flags a client that accesses many distinct paths, especially resulting in 404 responses."""

    rule_name: str = "Endpoint Probing"
    severity: AlertSeverity = AlertSeverity.HIGH

    def __init__(
        self,
        distinct_paths_threshold: Optional[int] = None,
        not_found_threshold: Optional[int] = None,
        window_seconds: Optional[int] = None,
    ) -> None:
        """Initialize rule with configurable distinct path threshold, 404 threshold, and window."""
        self.distinct_paths_threshold: int = (
            distinct_paths_threshold
            if distinct_paths_threshold is not None
            else settings.PROBING_DISTINCT_PATHS_THRESHOLD
        )
        self.not_found_threshold: int = (
            not_found_threshold
            if not_found_threshold is not None
            else settings.PROBING_404_THRESHOLD
        )
        self.window_seconds: int = (
            window_seconds
            if window_seconds is not None
            else settings.PROBING_WINDOW_SECONDS
        )

    def evaluate(
        self,
        client_id: str,
        logs: List[RequestLog],
        current_time: datetime,
    ) -> Optional[Alert]:
        """Check if client accesses excessive distinct paths with elevated 404 error counts."""
        cutoff = current_time - timedelta(seconds=self.window_seconds)

        window_logs = [log for log in logs if log.timestamp >= cutoff]

        distinct_paths: Set[str] = {log.path for log in window_logs}
        not_found_logs = [log for log in window_logs if log.status_code == 404]

        if (
            len(distinct_paths) >= self.distinct_paths_threshold
            and len(not_found_logs) >= self.not_found_threshold
        ):
            # Sort paths for deterministic evidence logging
            sample_paths = sorted(list(distinct_paths))[:10]

            return Alert(
                timestamp=current_time,
                client_id=client_id,
                rule_name=self.rule_name,
                severity=self.severity,
                reason=(
                    f"Client '{client_id}' accessed {len(distinct_paths)} distinct paths with "
                    f"{len(not_found_logs)} 404 responses within {self.window_seconds}s."
                ),
                evidence={
                    "distinct_paths_count": len(distinct_paths),
                    "distinct_paths": sample_paths,
                    "not_found_count": len(not_found_logs),
                    "distinct_paths_threshold": self.distinct_paths_threshold,
                    "not_found_threshold": self.not_found_threshold,
                    "window_seconds": self.window_seconds,
                },
                status=AlertStatus.OPEN,
            )

        return None
