"""Tests for demonstration API endpoints and request logging functionality."""

from fastapi.testclient import TestClient
import pytest

from app.core.config import settings
from app.repositories.log_repository import get_log_repository


# ==============================================================================
# Authentication Endpoint Tests (POST /api/login)
# ==============================================================================


def test_login_successful_with_valid_credentials(client: TestClient) -> None:
    """Verify that POST /api/login succeeds with valid test credentials."""
    response = client.post(
        "/api/login",
        json={"username": "admin", "password": "sentinel123"},
        headers={"X-Client-ID": "test-client-admin"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["username"] == "admin"
    assert "successful" in data["message"].lower()


def test_login_failure_with_invalid_password(client: TestClient) -> None:
    """Verify that POST /api/login returns HTTP 401 on incorrect password."""
    response = client.post(
        "/api/login",
        json={"username": "admin", "password": "wrong-password"},
        headers={"X-Client-ID": "attacker-01"},
    )
    assert response.status_code == 401
    data = response.json()
    assert "Invalid username or password" in data["detail"]


def test_login_failure_with_unknown_user(client: TestClient) -> None:
    """Verify that POST /api/login returns HTTP 401 for non-existent users."""
    response = client.post(
        "/api/login",
        json={"username": "nonexistent_user", "password": "any_password"},
        headers={"X-Client-ID": "attacker-02"},
    )
    assert response.status_code == 401


def test_login_validation_error_on_empty_payload(client: TestClient) -> None:
    """Verify that POST /api/login returns HTTP 422 when body is invalid."""
    response = client.post("/api/login", json={})
    assert response.status_code == 422


# ==============================================================================
# Products Endpoint Tests (GET /api/products, GET /api/products/{id})
# ==============================================================================


def test_list_products_returns_sample_catalog(client: TestClient) -> None:
    """Verify that GET /api/products returns the static catalog."""
    response = client.get("/api/products")
    assert response.status_code == 200
    products = response.json()
    assert isinstance(products, list)
    assert len(products) > 0
    assert products[0]["id"] == 1
    assert "name" in products[0]
    assert "price" in products[0]


def test_get_product_by_valid_id(client: TestClient) -> None:
    """Verify that GET /api/products/{id} returns the specific item."""
    response = client.get("/api/products/1")
    assert response.status_code == 200
    product = response.json()
    assert product["id"] == 1
    assert product["name"] == "Sentinel API Gateway"


def test_get_product_by_invalid_id_returns_404(client: TestClient) -> None:
    """Verify that GET /api/products/{id} returns HTTP 404 when item is missing."""
    response = client.get("/api/products/99999")
    assert response.status_code == 404
    data = response.json()
    assert "Product with ID 99999 not found" in data["detail"]


# ==============================================================================
# Request Logging Middleware & Repository Tests
# ==============================================================================


def test_request_logging_custom_client_id(client: TestClient) -> None:
    """Verify that X-Client-ID header value is recorded in request logs."""
    client.get("/api/products", headers={"X-Client-ID": "scanner-probe-42"})

    repo = get_log_repository()
    logs = repo.get_logs()
    assert len(logs) == 1
    assert logs[0].client_id == "scanner-probe-42"
    assert logs[0].method == "GET"
    assert logs[0].path == "/api/products"
    assert logs[0].status_code == 200


def test_request_logging_default_client_id_fallback(client: TestClient) -> None:
    """Verify that missing X-Client-ID header falls back to default client ID."""
    client.get("/health")

    repo = get_log_repository()
    logs = repo.get_logs()
    assert len(logs) == 1
    assert logs[0].client_id == settings.DEFAULT_CLIENT_ID
    assert logs[0].path == "/health"
    assert logs[0].status_code == 200


def test_request_logging_metadata_attributes(client: TestClient) -> None:
    """Verify all required telemetry fields are populated correctly."""
    response = client.get("/api/products/2", headers={"X-Client-ID": "test-agent"})
    assert response.status_code == 200

    repo = get_log_repository()
    logs = repo.get_logs()
    assert len(logs) == 1
    log = logs[0]

    assert log.client_id == "test-agent"
    assert log.method == "GET"
    assert log.path == "/api/products/2"
    assert log.status_code == 200
    assert log.process_time_ms >= 0.0
    assert log.timestamp is not None
    # Verify response header was attached
    assert "X-Process-Time-Ms" in response.headers


def test_request_logging_failed_requests_logged(client: TestClient) -> None:
    """Verify that failed requests (401, 404) are accurately recorded in logs."""
    client.post(
        "/api/login",
        json={"username": "admin", "password": "wrong"},
        headers={"X-Client-ID": "failed-auth-tester"},
    )
    client.get("/api/products/888", headers={"X-Client-ID": "not-found-tester"})

    repo = get_log_repository()
    assert repo.count_logs() == 2

    logs = repo.get_logs()
    # Newest log first
    assert logs[0].path == "/api/products/888"
    assert logs[0].status_code == 404
    assert logs[0].client_id == "not-found-tester"

    assert logs[1].path == "/api/login"
    assert logs[1].status_code == 401
    assert logs[1].client_id == "failed-auth-tester"


def test_no_duplicate_request_logging(client: TestClient) -> None:
    """Verify each HTTP request is logged exactly once."""
    repo = get_log_repository()
    initial_count = repo.count_logs()
    assert initial_count == 0

    client.get("/api/products")
    assert repo.count_logs() == 1

    client.get("/api/products/1")
    assert repo.count_logs() == 2


def test_safe_logging_never_stores_passwords_or_bodies(client: TestClient) -> None:
    """Verify that sensitive information (passwords, request bodies) is never stored."""
    secret_password = "very_sensitive_password_12345"
    client.post(
        "/api/login",
        json={"username": "admin", "password": secret_password},
        headers={"X-Client-ID": "security-tester"},
    )

    repo = get_log_repository()
    logs = repo.get_logs()
    assert len(logs) == 1
    log = logs[0]

    # Verify log attributes do not have payload/body attributes
    assert not hasattr(log, "password")
    assert not hasattr(log, "body")
    assert not hasattr(log, "payload")

    # Serialize to JSON string and ensure secret password never appears anywhere
    serialized_log = log.model_dump_json()
    assert secret_password not in serialized_log
    assert "admin" not in serialized_log  # username isn't even in log model


# ==============================================================================
# Audit Logs Endpoint Tests (GET /logs)
# ==============================================================================


def test_get_logs_endpoint_retrieves_records(client: TestClient) -> None:
    """Verify that GET /logs returns recorded requests."""
    # Issue requests to populate log
    client.get("/api/products", headers={"X-Client-ID": "agent-a"})
    client.get("/api/products/1", headers={"X-Client-ID": "agent-b"})

    # First GET /logs retrieves the 2 requests executed prior to this call
    response = client.get("/logs", headers={"X-Client-ID": "log-reader"})
    assert response.status_code == 200
    data = response.json()

    assert isinstance(data, list)
    assert len(data) == 2
    # Prior requests ordered newest first
    assert data[0]["path"] == "/api/products/1"
    assert data[0]["client_id"] == "agent-b"
    assert data[1]["path"] == "/api/products"
    assert data[1]["client_id"] == "agent-a"

    # After the /logs call finishes, the middleware logs it as well (total 3 in repo)
    repo = get_log_repository()
    assert repo.count_logs() == 3

    # A subsequent call to /logs now includes the previous /logs call
    second_response = client.get("/logs", headers={"X-Client-ID": "log-reader-2"})
    assert second_response.status_code == 200
    second_data = second_response.json()
    assert len(second_data) == 3
    assert second_data[0]["path"] == "/logs"
    assert second_data[0]["client_id"] == "log-reader"


def test_get_logs_pagination_and_limit(client: TestClient) -> None:
    """Verify that GET /logs pagination parameters limit and skip work correctly."""
    for i in range(5):
        client.get("/api/products", headers={"X-Client-ID": f"client-{i}"})

    response = client.get("/logs?limit=2&skip=1")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


def test_get_logs_exceeding_max_limit_rejected(client: TestClient) -> None:
    """Verify that requesting more than MAX_LOGS_LIMIT returns HTTP 422."""
    response = client.get(f"/logs?limit={settings.MAX_LOGS_LIMIT + 1}")
    assert response.status_code == 422
