"""Alert data schemas for security incidents and abuse events."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import uuid
from pydantic import BaseModel, Field, field_validator


class AlertSeverity(str, Enum):
    """Severity levels for generated security alerts."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Lifecycle statuses for security alerts."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Alert(BaseModel):
    """Schema representing a rule-based abuse or anomaly alert."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique alert identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the alert was triggered",
    )

    @field_validator("timestamp", mode="after")
    @classmethod
    def ensure_utc_timestamp(cls, v: datetime) -> datetime:
        """Ensure timestamp is timezone-aware UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v
    client_id: str = Field(
        ...,
        description="Identifier of the abusive or anomalous client",
    )
    rule_name: str = Field(
        ...,
        description="Name of the security detection rule that triggered",
    )
    severity: AlertSeverity = Field(
        default=AlertSeverity.MEDIUM,
        description="Severity classification of the incident",
    )
    reason: str = Field(
        ...,
        description="Human-readable explanation of why this alert was generated",
    )
    evidence: Dict[str, Any] = Field(
        default_factory=dict,
        description="Contextual metrics, counts, and indicators supporting the alert",
    )
    status: AlertStatus = Field(
        default=AlertStatus.OPEN,
        description="Current lifecycle status of the alert",
    )
