"""Feature extraction module for ML anomaly detection.

This module aggregates recent RequestLog records within a sliding observation window
and computes numerical features for Isolation Forest evaluation.

SECURITY & PRIVACY:
Feature extraction strictly relies on metadata counters (counts, proportions, paths).
Passwords, tokens, authorization headers, and raw payloads are never accessed or stored.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.models.log import RequestLog

FEATURE_NAMES: List[str] = [
    "request_count",
    "failed_login_count",
    "error_4xx_proportion",
    "distinct_paths_count",
    "not_found_count",
]


class ClientFeatures(BaseModel):
    """Aggregated numerical feature vector for an API client."""

    client_id: str = Field(..., description="Unique client identifier")
    observation_window_seconds: int = Field(
        ..., description="Length of observation window in seconds"
    )
    request_count: int = Field(default=0, description="Total requests within window")
    failed_login_count: int = Field(
        default=0, description="Failed login attempts (HTTP 401 on /api/login)"
    )
    error_4xx_proportion: float = Field(
        default=0.0, description="Proportion of 4xx responses (0.0 to 1.0)"
    )
    distinct_paths_count: int = Field(
        default=0, description="Number of distinct paths accessed"
    )
    not_found_count: int = Field(
        default=0, description="Number of HTTP 404 Not Found responses"
    )

    def to_vector(self, feature_names: Optional[List[str]] = None) -> List[float]:
        """Convert features to an ordered list of floats for model prediction."""
        names = feature_names or FEATURE_NAMES
        vector: List[float] = []
        for name in names:
            val = getattr(self, name, 0.0)
            vector.append(float(val))
        return vector

    def to_dict(self) -> Dict[str, Any]:
        """Return features as a clean dictionary."""
        return {
            "request_count": self.request_count,
            "failed_login_count": self.failed_login_count,
            "error_4xx_proportion": self.error_4xx_proportion,
            "distinct_paths_count": self.distinct_paths_count,
            "not_found_count": self.not_found_count,
        }


def extract_client_features(
    client_id: str,
    logs: List[RequestLog],
    current_time: datetime,
    window_seconds: int = 300,
) -> ClientFeatures:
    """Extract aggregated feature vector for a specific client over the observation window.

    Args:
        client_id: The target client identifier.
        logs: History of RequestLog items for this client.
        current_time: Current reference time (UTC).
        window_seconds: Size of observation window in seconds (defaults to 300s).

    Returns:
        ClientFeatures model populated with calculated metrics.
    """
    cutoff = current_time - timedelta(seconds=window_seconds)

    # Filter logs belonging to this client and within the observation window
    window_logs = [
        log
        for log in logs
        if log.client_id == client_id and log.timestamp >= cutoff
    ]

    request_count = len(window_logs)
    if request_count == 0:
        return ClientFeatures(
            client_id=client_id,
            observation_window_seconds=window_seconds,
            request_count=0,
            failed_login_count=0,
            error_4xx_proportion=0.0,
            distinct_paths_count=0,
            not_found_count=0,
        )

    # 1. Failed logins: POST to /api/login with 401 status
    failed_login_count = sum(
        1
        for log in window_logs
        if log.path == "/api/login"
        and log.method == "POST"
        and log.status_code == 401
    )

    # 2. 4xx errors
    error_4xx_count = sum(1 for log in window_logs if 400 <= log.status_code < 500)
    error_4xx_proportion = round(error_4xx_count / request_count, 4)

    # 3. Distinct paths
    distinct_paths = set(log.path for log in window_logs)
    distinct_paths_count = len(distinct_paths)

    # 4. 404 Not Found count
    not_found_count = sum(1 for log in window_logs if log.status_code == 404)

    return ClientFeatures(
        client_id=client_id,
        observation_window_seconds=window_seconds,
        request_count=request_count,
        failed_login_count=failed_login_count,
        error_4xx_proportion=error_4xx_proportion,
        distinct_paths_count=distinct_paths_count,
        not_found_count=not_found_count,
    )


def extract_features_for_all_clients(
    logs: List[RequestLog],
    current_time: datetime,
    window_seconds: int = 300,
) -> Dict[str, ClientFeatures]:
    """Group all active request logs within window by client and extract features.

    Args:
        logs: Collection of recent RequestLog items.
        current_time: Current reference time (UTC).
        window_seconds: Size of observation window in seconds.

    Returns:
        Dictionary mapping client_id to its ClientFeatures.
    """
    cutoff = current_time - timedelta(seconds=window_seconds)

    # Find distinct client IDs active in this window
    active_clients = set(
        log.client_id for log in logs if log.timestamp >= cutoff
    )

    results: Dict[str, ClientFeatures] = {}
    for cid in active_clients:
        results[cid] = extract_client_features(
            client_id=cid,
            logs=logs,
            current_time=current_time,
            window_seconds=window_seconds,
        )
    return results
