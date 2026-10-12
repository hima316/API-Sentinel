"""Authentication models and dummy test credentials.

NOTE: This is a demonstration API designed for activity generation and anomaly
monitoring. Never use plain dummy credentials or hardcoded passwords in production.
"""

from typing import Dict
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    """Schema for simulated login requests."""

    username: str = Field(
        ...,
        min_length=1,
        description="Demo account username",
        examples=["admin"],
    )
    password: str = Field(
        ...,
        min_length=1,
        description="Demo account password",
        examples=["sentinel123"],
    )


class LoginResponse(BaseModel):
    """Schema for simulated login responses."""

    success: bool = Field(..., description="Whether authentication was successful")
    message: str = Field(..., description="Status message")
    username: str = Field(..., description="The authenticated username")


# Clearly documented demonstration test credentials
# These are used to generate test traffic (both successful logins and failed brute-force attempts).
DUMMY_CREDENTIALS: Dict[str, str] = {
    "admin": "sentinel123",
    "analyst": "guard456",
    "testuser": "password123",
}
