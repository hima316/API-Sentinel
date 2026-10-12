"""Request log data model.

This schema defines safe request metadata captured by the logging middleware.
It strictly excludes sensitive data such as request bodies, passwords, query tokens,
or authorization headers.
"""

from datetime import datetime, timezone
from typing import Optional
import uuid
from pydantic import BaseModel, Field, field_validator


class RequestLog(BaseModel):
    """Schema representing an audited API request event."""

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique log entry identifier",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the request occurred",
    )
    client_id: str = Field(
        ...,
        description="Identifier of the client (from X-Client-ID or fallback default)",
    )
    method: str = Field(..., description="HTTP method (e.g., GET, POST)")
    path: str = Field(..., description="Request URL path (e.g., /api/login)")
    status_code: int = Field(..., description="HTTP response status code")
    process_time_ms: float = Field(
        ...,
        description="Server processing duration in milliseconds",
    )

    @field_validator("timestamp", mode="after")
    @classmethod
    def ensure_utc_timestamp(cls, v: datetime) -> datetime:
        """Ensure timestamp is timezone-aware UTC."""
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v
