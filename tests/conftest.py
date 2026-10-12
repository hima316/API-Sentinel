"""Pytest fixtures for API Sentinel test suite."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ml.detector import set_anomaly_detector
from app.repositories.alert_repository import get_alert_repository
from app.repositories.log_repository import get_log_repository


@pytest.fixture(autouse=True)
def clean_storage():
    """Clear in-memory request logs and alerts before and after each test."""
    set_anomaly_detector(None)
    log_repo = get_log_repository()
    alert_repo = get_alert_repository()
    log_repo.clear_logs()
    alert_repo.clear_alerts()
    yield
    set_anomaly_detector(None)
    log_repo.clear_logs()
    alert_repo.clear_alerts()


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient instance for issuing HTTP requests."""
    return TestClient(app)
