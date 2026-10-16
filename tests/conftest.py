"""Pytest fixtures for API Sentinel test suite."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.ml.detector import set_anomaly_detector
from app.repositories.alert_repository import (
    InMemoryAlertRepository,
    get_alert_repository,
    set_alert_repository,
)
from app.repositories.log_repository import (
    InMemoryLogRepository,
    get_log_repository,
    set_log_repository,
)


@pytest.fixture(autouse=True)
def clean_storage():
    """Clear in-memory request logs and alerts before and after each test."""
    set_anomaly_detector(None)
    in_mem_logs = InMemoryLogRepository()
    in_mem_alerts = InMemoryAlertRepository()
    set_log_repository(in_mem_logs)
    set_alert_repository(in_mem_alerts)
    yield
    set_anomaly_detector(None)
    in_mem_logs.clear_logs()
    in_mem_alerts.clear_alerts()


@pytest.fixture
def client() -> TestClient:
    """Provide a TestClient instance for issuing HTTP requests."""
    return TestClient(app)
