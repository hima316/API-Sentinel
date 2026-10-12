"""Rule-based API abuse detection package."""

from app.rules.base import BaseRule
from app.rules.endpoint_probing import EndpointProbingRule
from app.rules.engine import (
    AbuseDetectionEngine,
    get_detection_engine,
    set_detection_engine,
)
from app.rules.failed_logins import RepeatedFailedLoginsRule
from app.rules.request_burst import RequestBurstRule

__all__ = [
    "BaseRule",
    "RepeatedFailedLoginsRule",
    "RequestBurstRule",
    "EndpointProbingRule",
    "AbuseDetectionEngine",
    "get_detection_engine",
    "set_detection_engine",
]
