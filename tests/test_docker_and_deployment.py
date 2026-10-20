"""Tests for Docker packaging, configuration, security hardening, and deployment readiness."""

from pathlib import Path
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.database.mongodb import DatabaseConnectionError, DatabaseOperationError
from app.main import app


# ==============================================================================
# Dockerfile and Container Configuration Tests
# ==============================================================================


def test_dockerfile_exists_and_meets_security_standards() -> None:
    """Verify Dockerfile exists and enforces container security best practices."""
    dockerfile_path = Path("Dockerfile")
    assert dockerfile_path.exists(), "Dockerfile must exist in project root"

    content = dockerfile_path.read_text(encoding="utf-8")

    # Base image must be lightweight official Python slim
    assert "FROM python:3.11-slim" in content or "FROM python:3.12-slim" in content

    # Must configure non-root user for security
    assert "useradd" in content or "adduser" in content
    assert "USER appuser" in content

    # Must expose port and allow configurable port binding
    assert "EXPOSE 8000" in content
    assert "${PORT" in content or "$PORT" in content

    # Must include healthcheck
    assert "HEALTHCHECK" in content
    assert "/health" in content

    # Must ensure ML model artifact availability (trains deterministically if missing)
    assert "models/isolation_forest.joblib" in content
    assert "train_isolation_forest.py" in content


def test_dockerignore_excludes_secrets_and_development_artifacts() -> None:
    """Verify .dockerignore excludes sensitive files and unnecessary development files."""
    dockerignore_path = Path(".dockerignore")
    assert dockerignore_path.exists(), ".dockerignore must exist in project root"

    content = dockerignore_path.read_text(encoding="utf-8")
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]

    # Critical security: Must ignore .env files
    assert any(".env" in line for line in lines), ".dockerignore must exclude .env"
    assert any(".git" in line for line in lines), ".dockerignore must exclude .git"
    assert any(".venv" in line for line in lines), ".dockerignore must exclude .venv"
    assert any("__pycache__" in line for line in lines), ".dockerignore must exclude __pycache__"

    # Must NOT exclude core app code or models
    assert not any(line == "app" or line == "app/" for line in lines), "Must not exclude app/"
    assert not any(line == "models" or line == "models/" for line in lines), "Must not exclude models/"


def test_docker_compose_exists_and_configured() -> None:
    """Verify docker-compose.yml exists and uses environment-based configuration."""
    compose_path = Path("docker-compose.yml")
    assert compose_path.exists(), "docker-compose.yml must exist in project root"

    content = compose_path.read_text(encoding="utf-8")
    assert "services:" in content
    assert "api-sentinel:" in content
    assert "HEALTHCHECK" in content or "healthcheck:" in content
    assert "STORAGE_BACKEND" in content


# ==============================================================================
# Security Exception Handlers & Information Leakage Prevention
# ==============================================================================


def test_database_connection_error_handler_safeguard() -> None:
    """Verify DatabaseConnectionError returns HTTP 503 and does not leak credentials or traces."""
    from app.repositories.log_repository import get_log_repository
    from unittest.mock import MagicMock

    mock_repo = MagicMock()
    mock_repo.get_logs.side_effect = DatabaseConnectionError(
        "Connection failed to mongodb+srv://admin:mockpassword@cluster0.example.com"
    )

    app.dependency_overrides[get_log_repository] = lambda: mock_repo
    try:
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/logs")
        assert response.status_code == 503
        data = response.json()
        assert "detail" in data
        assert "mockpassword" not in response.text
        assert "Traceback" not in response.text
        assert data["detail"] == "Database service is temporarily unavailable."
    finally:
        app.dependency_overrides.clear()


def test_database_operation_error_handler_safeguard() -> None:
    """Verify DatabaseOperationError returns HTTP 500 and prevents stack trace disclosure."""
    from app.repositories.log_repository import get_log_repository
    from unittest.mock import MagicMock

    mock_repo = MagicMock()
    mock_repo.get_logs.side_effect = DatabaseOperationError(
        "Write failed due to primary stepdown"
    )

    app.dependency_overrides[get_log_repository] = lambda: mock_repo
    try:
        client = TestClient(app, raise_server_exceptions=False)
        response = client.get("/logs")
        assert response.status_code == 500
        data = response.json()
        assert "detail" in data
        assert "Traceback" not in response.text
        assert data["detail"] == "A database operation error occurred."
    finally:
        app.dependency_overrides.clear()


# ==============================================================================
# Production Settings & Healthcheck Preservation Tests
# ==============================================================================


def test_healthcheck_endpoint_contract() -> None:
    """Verify /health endpoint returns required production metadata without sensitive details."""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "app_name" in data
    assert "environment" in data
    assert "version" in data
    # Must never expose database connection strings, passwords, or system paths
    assert "mongodb" not in response.text.lower()
    assert "password" not in response.text.lower()


def test_production_settings_overrides() -> None:
    """Verify Settings class properly accepts production container environment variables."""
    prod_settings = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        HOST="0.0.0.0",
        PORT=8080,
        STORAGE_BACKEND="mongodb",
        MONGODB_URI="mongodb+srv://user:pass@cluster0.example.com",
    )
    assert prod_settings.ENVIRONMENT == "production"
    assert prod_settings.DEBUG is False
    assert prod_settings.HOST == "0.0.0.0"
    assert prod_settings.PORT == 8080
    assert prod_settings.STORAGE_BACKEND == "mongodb"
