"""Tests for the API Sentinel health check and core endpoints."""

from fastapi.testclient import TestClient
import pytest

from app.core.config import Settings, get_settings
from app.main import app

client = TestClient(app)


def test_health_check_status_code() -> None:
    """Verify that GET /health returns HTTP 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200


def test_health_check_payload() -> None:
    """Verify that GET /health returns expected fields and values."""
    response = client.get("/health")
    data = response.json()

    assert data["status"] == "healthy"
    assert data["app_name"] == "API Sentinel"
    assert "environment" in data
    assert "version" in data


def test_root_endpoint() -> None:
    """Verify that GET / returns a welcoming response with docs link."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Welcome to API Sentinel" in data["message"]
    assert data["docs_url"] == "/docs"


def test_openapi_schema_title() -> None:
    """Verify that OpenAPI documentation metadata matches configuration."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "API Sentinel"


def test_docs_page_available() -> None:
    """Verify that Swagger UI documentation endpoint (/docs) responds with 200."""
    response = client.get("/docs")
    assert response.status_code == 200


def test_settings_configuration() -> None:
    """Verify that default settings load with expected values."""
    settings = get_settings()
    assert isinstance(settings, Settings)
    assert settings.PROJECT_NAME == "API Sentinel"
    assert settings.ENVIRONMENT == "development"
    assert settings.DEBUG is True
