"""Orchestration engine for rule-based API abuse detection.

This engine executes configured rules against recent request traffic for a given client,
enforces cooldown deduplication to prevent alert spamming during ongoing incidents,
and persists genuine new alerts to the alert repository.
"""

from datetime import datetime, timezone
import threading
from typing import List, Optional

from app.core.config import settings
from app.models.alert import Alert
from app.repositories.alert_repository import (
    BaseAlertRepository,
    get_alert_repository,
)
from app.repositories.log_repository import (
    BaseLogRepository,
    get_log_repository,
)
from app.rules.base import BaseRule
from app.rules.endpoint_probing import EndpointProbingRule
from app.rules.failed_logins import RepeatedFailedLoginsRule
from app.rules.request_burst import RequestBurstRule


class AbuseDetectionEngine:
    """Evaluates request traffic against abuse rules with cooldown deduplication."""

    def __init__(
        self,
        rules: Optional[List[BaseRule]] = None,
        log_repository: Optional[BaseLogRepository] = None,
        alert_repository: Optional[BaseAlertRepository] = None,
        cooldown_seconds: Optional[int] = None,
    ) -> None:
        """Initialize the detection engine.

        Args:
            rules: List of BaseRule evaluators. Defaults to standard rule set.
            log_repository: Repository to fetch request history from.
            alert_repository: Repository to store alerts and query for deduplication.
            cooldown_seconds: Minimum time between successive alerts for same client & rule.
        """
        self.rules: List[BaseRule] = (
            rules
            if rules is not None
            else [
                RepeatedFailedLoginsRule(),
                RequestBurstRule(),
                EndpointProbingRule(),
            ]
        )
        self._log_repository = log_repository
        self._alert_repository = alert_repository
        self.cooldown_seconds: int = (
            cooldown_seconds
            if cooldown_seconds is not None
            else settings.ALERT_COOLDOWN_SECONDS
        )
        self._lock = threading.Lock()

    @property
    def log_repo(self) -> BaseLogRepository:
        """Return the active log repository."""
        return self._log_repository or get_log_repository()

    @property
    def alert_repo(self) -> BaseAlertRepository:
        """Return the active alert repository."""
        return self._alert_repository or get_alert_repository()

    def evaluate_client(
        self,
        client_id: str,
        current_time: Optional[datetime] = None,
    ) -> List[Alert]:
        """Evaluate a client against all rules and persist any non-duplicate alerts.

        Args:
            client_id: Identifier of the client to inspect.
            current_time: Evaluation time (defaults to datetime.now(timezone.utc)).

        Returns:
            List of newly created Alert instances (empty if none fired or suppressed).
        """
        now = current_time or datetime.now(timezone.utc)

        # Retrieve recent logs for this client.
        # Window of 300 seconds is enough to cover all configured rule windows.
        max_window = max(
            settings.FAILED_LOGIN_WINDOW_SECONDS,
            settings.BURST_WINDOW_SECONDS,
            settings.PROBING_WINDOW_SECONDS,
            300,
        )
        recent_logs = self.log_repo.get_logs_for_client(
            client_id=client_id,
            limit=500,
        )

        new_alerts: List[Alert] = []

        with self._lock:
            for rule in self.rules:
                candidate_alert = rule.evaluate(
                    client_id=client_id,
                    logs=recent_logs,
                    current_time=now,
                )

                if candidate_alert is None:
                    continue

                # Deduplication / Cooldown Check:
                # Prevent spamming alerts for every subsequent request during an incident.
                latest_alert = self.alert_repo.get_latest_alert_for_rule(
                    client_id=client_id,
                    rule_name=candidate_alert.rule_name,
                )

                if latest_alert is not None:
                    elapsed = (now - latest_alert.timestamp).total_seconds()
                    if elapsed < self.cooldown_seconds:
                        # Within cooldown window; suppress duplicate alert
                        continue

                # Cooldown satisfied; record and persist the new alert
                persisted_alert = self.alert_repo.add_alert(candidate_alert)
                new_alerts.append(persisted_alert)

        return new_alerts


# Global detection engine singleton
_detection_engine_instance: Optional[AbuseDetectionEngine] = None


def get_detection_engine() -> AbuseDetectionEngine:
    """Dependency provider for the active AbuseDetectionEngine."""
    global _detection_engine_instance
    if _detection_engine_instance is None:
        _detection_engine_instance = AbuseDetectionEngine()
    return _detection_engine_instance


def set_detection_engine(engine: AbuseDetectionEngine) -> None:
    """Override active detection engine instance (useful for testing)."""
    global _detection_engine_instance
    _detection_engine_instance = engine
