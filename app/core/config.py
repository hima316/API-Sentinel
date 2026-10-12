"""Application configuration settings managed by Pydantic Settings.

This module defines configuration settings for the API Sentinel platform.
Values are automatically read from environment variables or a local `.env` file,
with sensible defaults provided for development.
"""

from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings class.

    Attributes:
        PROJECT_NAME: Human-readable name of the application.
        PROJECT_DESCRIPTION: Summary description for OpenAPI documentation.
        VERSION: Current version of the service.
        ENVIRONMENT: Runtime environment (e.g., 'development', 'staging', 'production').
        DEBUG: Flag to toggle debug mode.
        HOST: Host address for running the Uvicorn server.
        PORT: Port number for the server.
        API_V1_PREFIX: Route prefix for version 1 API endpoints.
    """

    PROJECT_NAME: str = "API Sentinel"
    PROJECT_DESCRIPTION: str = "API Abuse & Anomaly Detection Platform"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    HOST: str = "127.0.0.1"
    PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"

    # Request Logging & Client Identification Configuration
    DEFAULT_CLIENT_ID: str = "anonymous-client"
    CLIENT_ID_HEADER: str = "X-Client-ID"
    DEFAULT_LOGS_LIMIT: int = 50
    MAX_LOGS_LIMIT: int = 100

    # Rule-Based Abuse Detection Configuration
    # Rule 1: Repeated Failed Logins
    FAILED_LOGIN_THRESHOLD: int = 5
    FAILED_LOGIN_WINDOW_SECONDS: int = 60

    # Rule 2: Request Burst
    BURST_REQUEST_THRESHOLD: int = 30
    BURST_WINDOW_SECONDS: int = 10

    # Rule 3: Endpoint Probing
    PROBING_DISTINCT_PATHS_THRESHOLD: int = 5
    PROBING_404_THRESHOLD: int = 3
    PROBING_WINDOW_SECONDS: int = 60

    # Alert Deduplication / Cooldown Window
    ALERT_COOLDOWN_SECONDS: int = 60
    DEFAULT_ALERTS_LIMIT: int = 50
    MAX_ALERTS_LIMIT: int = 100

    # Storage Backend Configuration
    STORAGE_BACKEND: str = "memory"  # Options: 'memory' or 'mongodb'
    MONGODB_URI: Optional[str] = None
    MONGODB_DATABASE: str = "api_sentinel"
    MONGODB_CONNECT_TIMEOUT_MS: int = 5000
    MONGODB_SERVER_SELECTION_TIMEOUT_MS: int = 5000
    MONGODB_REQUEST_LOGS_COLLECTION: str = "request_logs"
    MONGODB_SECURITY_ALERTS_COLLECTION: str = "security_alerts"

    # ML Anomaly Detection Configuration
    ML_MODEL_PATH: str = "models/isolation_forest.joblib"
    ML_METADATA_PATH: str = "models/model_metadata.json"
    ML_OBSERVATION_WINDOW_SECONDS: int = 300
    ML_CONTAMINATION: float = 0.05
    ML_RANDOM_STATE: int = 42
    ML_ALERT_COOLDOWN_SECONDS: int = 300

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached instance of application settings.

    Using lru_cache ensures the settings file is only read once from disk.
    """
    return Settings()


# Global settings instance for easy importing across the application
settings: Settings = get_settings()
