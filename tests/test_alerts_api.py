"""Tests for Security Alerts endpoints (GET /alerts, GET /alerts/{alert_id}) and live detection."""

from fastapi.testclient import TestClient
import pytest

from app.core.config import settings
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.repositories.alert_repository import get_alert_repository


# ==============================================================================
# Direct Alert Endpoint Tests (GET /alerts, GET /alerts/{id})
# ==============================================================================


def test_get_alerts_initially_empty(client: TestClient) -> None:
    """Verify that GET /alerts returns an empty list when no alerts exist."""
    response = client.get("/alerts")
    assert response.status_code == 200
    assert response.json() == []


def test_get_alerts_retrieves_stored_alerts(client: TestClient) -> None:
    """Verify that GET /alerts returns persisted alerts with expected fields."""
    repo = get_alert_repository()
    alert1 = Alert(
        client_id="attacker-x",
        rule_name="Repeated Failed Logins",
        severity=AlertSeverity.HIGH,
        reason="Repeated failed logins detected",
        evidence={"failed_attempts": 5},
        status=AlertStatus.OPEN,
    )
    repo.add_alert(alert1)

    response = client.get("/alerts")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["id"] == alert1.id
    assert data[0]["client_id"] == "attacker-x"
    assert data[0]["rule_name"] == "Repeated Failed Logins"
    assert data[0]["severity"] == "high"
    assert data[0]["status"] == "open"
    assert data[0]["evidence"]["failed_attempts"] == 5


def test_get_alert_by_id_success(client: TestClient) -> None:
    """Verify that GET /alerts/{id} returns the specific alert."""
    repo = get_alert_repository()
    alert = Alert(
        client_id="target-client",
        rule_name="Request Burst",
        severity=AlertSeverity.MEDIUM,
        reason="Burst traffic exceeded threshold",
        evidence={"request_count": 35},
        status=AlertStatus.OPEN,
    )
    repo.add_alert(alert)

    response = client.get(f"/alerts/{alert.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == alert.id
    assert data["client_id"] == "target-client"
    assert data["rule_name"] == "Request Burst"


def test_get_alert_by_id_not_found(client: TestClient) -> None:
    """Verify that GET /alerts/{id} returns HTTP 404 for non-existent alerts."""
    response = client.get("/alerts/non-existent-alert-uuid")
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["detail"].lower()


def test_get_alerts_filtering_by_client_id_and_status(client: TestClient) -> None:
    """Verify filtering alerts by client_id and status query parameters."""
    repo = get_alert_repository()
    a1 = Alert(client_id="client-a", rule_name="Rule A", reason="r1", status=AlertStatus.OPEN)
    a2 = Alert(client_id="client-b", rule_name="Rule B", reason="r2", status=AlertStatus.ACKNOWLEDGED)
    a3 = Alert(client_id="client-a", rule_name="Rule C", reason="r3", status=AlertStatus.RESOLVED)
    repo.add_alert(a1)
    repo.add_alert(a2)
    repo.add_alert(a3)

    # Filter by client_id=client-a
    res_client = client.get("/alerts?client_id=client-a")
    assert res_client.status_code == 200
    assert len(res_client.json()) == 2

    # Filter by status=open
    res_status = client.get("/alerts?status=open")
    assert res_status.status_code == 200
    assert len(res_status.json()) == 1
    assert res_status.json()[0]["client_id"] == "client-a"


def test_get_alerts_pagination_and_limit_validation(client: TestClient) -> None:
    """Verify limit/skip pagination and maximum limit validation."""
    repo = get_alert_repository()
    for i in range(5):
        repo.add_alert(
            Alert(client_id=f"client-{i}", rule_name="Rule", reason="r")
        )

    # Pagination: limit 2, skip 1
    res = client.get("/alerts?limit=2&skip=1")
    assert res.status_code == 200
    assert len(res.json()) == 2

    # Limit validation: exceeding max limit returns 422
    res_overflow = client.get(f"/alerts?limit={settings.MAX_ALERTS_LIMIT + 1}")
    assert res_overflow.status_code == 422


# ==============================================================================
# End-to-End Live Detection Trigger Tests
# ==============================================================================


def test_e2e_repeated_failed_logins_triggers_live_alert(client: TestClient) -> None:
    """End-to-end: consecutive failed login calls automatically generate an alert."""
    bad_actor = "brute-forcer-99"

    # Issue 5 consecutive failed logins (default threshold = 5)
    for _ in range(5):
        response = client.post(
            "/api/login",
            json={"username": "admin", "password": "wrong-password-guess"},
            headers={"X-Client-ID": bad_actor},
        )
        assert response.status_code == 401

    # Check that an alert was generated and is accessible via GET /alerts
    alerts_response = client.get(f"/alerts?client_id={bad_actor}")
    assert alerts_response.status_code == 200
    alerts = alerts_response.json()

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Repeated Failed Logins"
    assert alerts[0]["client_id"] == bad_actor
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["status"] == "open"
    assert alerts[0]["evidence"]["failed_attempts"] == 5


def test_e2e_probing_triggers_live_alert(client: TestClient) -> None:
    """End-to-end: probing 5 distinct paths with 404s triggers an Endpoint Probing alert."""
    scanner_id = "path-fuzzer-01"

    # Send requests to 5 distinct non-existent endpoints (returns 404)
    probed_paths = [
        "/admin.php",
        "/.git/config",
        "/etc/passwd",
        "/api/secret-v2",
        "/phpmyadmin",
    ]
    for path in probed_paths:
        client.get(path, headers={"X-Client-ID": scanner_id})

    alerts_response = client.get(f"/alerts?client_id={scanner_id}")
    assert alerts_response.status_code == 200
    alerts = alerts_response.json()

    assert len(alerts) == 1
    assert alerts[0]["rule_name"] == "Endpoint Probing"
    assert alerts[0]["client_id"] == scanner_id
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["evidence"]["distinct_paths_count"] == 5
    assert alerts[0]["evidence"]["not_found_count"] == 5


def test_e2e_normal_traffic_generates_no_alerts(client: TestClient) -> None:
    """End-to-end: legitimate user browsing catalog and authenticating creates no alerts."""
    normal_client = "customer-jane"

    # Check health, browse catalog, view item, log in successfully
    client.get("/health", headers={"X-Client-ID": normal_client})
    client.get("/api/products", headers={"X-Client-ID": normal_client})
    client.get("/api/products/1", headers={"X-Client-ID": normal_client})
    client.post(
        "/api/login",
        json={"username": "admin", "password": "sentinel123"},
        headers={"X-Client-ID": normal_client},
    )

    alerts_response = client.get(f"/alerts?client_id={normal_client}")
    assert alerts_response.status_code == 200
    assert alerts_response.json() == []
