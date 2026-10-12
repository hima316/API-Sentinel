"""Deterministic unit tests for rule-based abuse detection evaluators and engine."""

from datetime import datetime, timedelta, timezone
from typing import List
import pytest

from app.models.alert import AlertSeverity, AlertStatus
from app.models.log import RequestLog
from app.repositories.alert_repository import InMemoryAlertRepository
from app.repositories.log_repository import InMemoryLogRepository
from app.rules.endpoint_probing import EndpointProbingRule
from app.rules.engine import AbuseDetectionEngine
from app.rules.failed_logins import RepeatedFailedLoginsRule
from app.rules.request_burst import RequestBurstRule


# ==============================================================================
# Helper to generate synthetic RequestLog entries with deterministic timestamps
# ==============================================================================


def create_log(
    client_id: str,
    path: str,
    status_code: int = 200,
    method: str = "GET",
    timestamp: datetime = None,
    process_time_ms: float = 1.5,
) -> RequestLog:
    """Helper to build a deterministic RequestLog fixture."""
    return RequestLog(
        timestamp=timestamp or datetime.now(timezone.utc),
        client_id=client_id,
        method=method,
        path=path,
        status_code=status_code,
        process_time_ms=process_time_ms,
    )


# ==============================================================================
# Rule 1: Repeated Failed Logins Tests
# ==============================================================================


def test_repeated_failed_logins_triggers_at_threshold() -> None:
    """Rule should trigger an alert when failed logins meet or exceed threshold."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = RepeatedFailedLoginsRule(threshold=5, window_seconds=60)

    # 5 failed login attempts within 60s
    logs = [
        create_log(
            client_id="attacker-1",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=i * 5),
        )
        for i in range(5)
    ]

    alert = rule.evaluate(client_id="attacker-1", logs=logs, current_time=now)
    assert alert is not None
    assert alert.rule_name == "Repeated Failed Logins"
    assert alert.client_id == "attacker-1"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.status == AlertStatus.OPEN
    assert alert.evidence["failed_attempts"] == 5
    assert alert.evidence["threshold"] == 5
    assert "failed login attempts" in alert.reason.lower()


def test_repeated_failed_logins_below_threshold_does_not_trigger() -> None:
    """Rule should NOT trigger when failed logins count is below threshold."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = RepeatedFailedLoginsRule(threshold=5, window_seconds=60)

    # 4 failed login attempts (below threshold of 5)
    logs = [
        create_log(
            client_id="user-1",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=i * 5),
        )
        for i in range(4)
    ]

    alert = rule.evaluate(client_id="user-1", logs=logs, current_time=now)
    assert alert is None


def test_repeated_failed_logins_ignores_successful_logins() -> None:
    """Successful logins (HTTP 200) must NOT count toward failed login threshold."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = RepeatedFailedLoginsRule(threshold=5, window_seconds=60)

    # 2 failed and 4 successful logins
    logs = [
        create_log(
            client_id="user-2",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=10),
        ),
        create_log(
            client_id="user-2",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=5),
        ),
    ] + [
        create_log(
            client_id="user-2",
            path="/api/login",
            status_code=200,
            method="POST",
            timestamp=now - timedelta(seconds=i),
        )
        for i in range(4)
    ]

    alert = rule.evaluate(client_id="user-2", logs=logs, current_time=now)
    assert alert is None


def test_repeated_failed_logins_ignores_expired_window_attempts() -> None:
    """Failed logins older than the window must not trigger the rule."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = RepeatedFailedLoginsRule(threshold=5, window_seconds=60)

    # 5 failed attempts, but 4 occurred > 60 seconds ago
    logs = [
        create_log(
            client_id="user-3",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=10),
        ),
        create_log(
            client_id="user-3",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=65),
        ),
        create_log(
            client_id="user-3",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=70),
        ),
        create_log(
            client_id="user-3",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=80),
        ),
        create_log(
            client_id="user-3",
            path="/api/login",
            status_code=401,
            method="POST",
            timestamp=now - timedelta(seconds=90),
        ),
    ]

    alert = rule.evaluate(client_id="user-3", logs=logs, current_time=now)
    assert alert is None


# ==============================================================================
# Rule 2: Request Burst Tests
# ==============================================================================


def test_request_burst_triggers_at_threshold() -> None:
    """Rule should trigger an alert when request volume reaches burst threshold."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = RequestBurstRule(threshold=30, window_seconds=10)

    # 30 requests within 10 seconds
    logs = [
        create_log(
            client_id="bot-burst",
            path="/api/products",
            status_code=200,
            timestamp=now - timedelta(seconds=i * 0.2),
        )
        for i in range(30)
    ]

    alert = rule.evaluate(client_id="bot-burst", logs=logs, current_time=now)
    assert alert is not None
    assert alert.rule_name == "Request Burst"
    assert alert.client_id == "bot-burst"
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.evidence["request_count"] == 30
    assert alert.evidence["threshold"] == 30
    assert alert.evidence["window_seconds"] == 10


def test_request_burst_below_threshold_does_not_trigger() -> None:
    """Rule should NOT trigger when request volume is below burst threshold."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = RequestBurstRule(threshold=30, window_seconds=10)

    # 29 requests within 10 seconds
    logs = [
        create_log(
            client_id="legit-user",
            path="/api/products",
            status_code=200,
            timestamp=now - timedelta(seconds=i * 0.2),
        )
        for i in range(29)
    ]

    alert = rule.evaluate(client_id="legit-user", logs=logs, current_time=now)
    assert alert is None


def test_request_burst_ignores_old_requests() -> None:
    """Requests outside the burst window should not count toward burst threshold."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = RequestBurstRule(threshold=30, window_seconds=10)

    # 35 requests total, but only 10 inside the 10-second window
    logs = [
        create_log(
            client_id="slow-bot",
            path="/api/products",
            timestamp=now - timedelta(seconds=i),
        )
        for i in range(10)
    ] + [
        create_log(
            client_id="slow-bot",
            path="/api/products",
            timestamp=now - timedelta(seconds=15 + i),
        )
        for i in range(25)
    ]

    alert = rule.evaluate(client_id="slow-bot", logs=logs, current_time=now)
    assert alert is None


# ==============================================================================
# Rule 3: Endpoint Probing Tests
# ==============================================================================


def test_endpoint_probing_triggers_on_distinct_paths_and_404s() -> None:
    """Rule should trigger when client probes distinct paths with multiple 404 responses."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = EndpointProbingRule(
        distinct_paths_threshold=5,
        not_found_threshold=3,
        window_seconds=60,
    )

    # 5 distinct paths probed, 3 of which return 404
    paths_and_statuses = [
        ("/admin/config", 404),
        ("/.env", 404),
        ("/wp-login.php", 404),
        ("/api/products", 200),
        ("/health", 200),
    ]

    logs = [
        create_log(
            client_id="vulnerability-scanner",
            path=path,
            status_code=status,
            timestamp=now - timedelta(seconds=i * 2),
        )
        for i, (path, status) in enumerate(paths_and_statuses)
    ]

    alert = rule.evaluate(
        client_id="vulnerability-scanner", logs=logs, current_time=now
    )
    assert alert is not None
    assert alert.rule_name == "Endpoint Probing"
    assert alert.client_id == "vulnerability-scanner"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.evidence["distinct_paths_count"] == 5
    assert alert.evidence["not_found_count"] == 3
    assert len(alert.evidence["distinct_paths"]) == 5


def test_endpoint_probing_repeated_same_path_does_not_trigger() -> None:
    """Repeated 404s on the SAME single path must NOT trigger probing rule."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = EndpointProbingRule(
        distinct_paths_threshold=5,
        not_found_threshold=3,
        window_seconds=60,
    )

    # 10 404 errors, but all against the identical path /api/products/999
    logs = [
        create_log(
            client_id="broken-link-clicker",
            path="/api/products/999",
            status_code=404,
            timestamp=now - timedelta(seconds=i * 2),
        )
        for i in range(10)
    ]

    alert = rule.evaluate(
        client_id="broken-link-clicker", logs=logs, current_time=now
    )
    assert alert is None


def test_endpoint_probing_distinct_valid_paths_does_not_trigger() -> None:
    """Accessing many valid endpoints (HTTP 200) without 404s must NOT trigger probing rule."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    rule = EndpointProbingRule(
        distinct_paths_threshold=5,
        not_found_threshold=3,
        window_seconds=60,
    )

    # 6 distinct paths, but all return HTTP 200
    valid_paths = [
        "/api/products",
        "/api/products/1",
        "/api/products/2",
        "/api/products/3",
        "/health",
        "/",
    ]

    logs = [
        create_log(
            client_id="legitimate-crawler",
            path=path,
            status_code=200,
            timestamp=now - timedelta(seconds=i * 2),
        )
        for i, path in enumerate(valid_paths)
    ]

    alert = rule.evaluate(
        client_id="legitimate-crawler", logs=logs, current_time=now
    )
    assert alert is None


# ==============================================================================
# AbuseDetectionEngine & Cooldown Deduplication Tests
# ==============================================================================


def test_normal_client_activity_generates_zero_alerts() -> None:
    """Normal legitimate client workflow must never trigger any alerts."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    log_repo = InMemoryLogRepository()
    alert_repo = InMemoryAlertRepository()

    engine = AbuseDetectionEngine(
        log_repository=log_repo,
        alert_repository=alert_repo,
    )

    # Normal user workflow: check health, browse products, view product 1, log in
    normal_logs = [
        create_log("normal-user-1", "/health", 200, timestamp=now - timedelta(seconds=30)),
        create_log("normal-user-1", "/api/products", 200, timestamp=now - timedelta(seconds=25)),
        create_log("normal-user-1", "/api/products/1", 200, timestamp=now - timedelta(seconds=20)),
        create_log("normal-user-1", "/api/login", 200, method="POST", timestamp=now - timedelta(seconds=15)),
    ]
    for log in normal_logs:
        log_repo.add_log(log)

    alerts = engine.evaluate_client("normal-user-1", current_time=now)
    assert len(alerts) == 0
    assert alert_repo.count_alerts() == 0


def test_alert_cooldown_deduplication() -> None:
    """Engine must suppress duplicate alerts for the same client and rule during cooldown."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    log_repo = InMemoryLogRepository()
    alert_repo = InMemoryAlertRepository()

    # Rule with threshold of 5, cooldown of 60 seconds
    engine = AbuseDetectionEngine(
        rules=[RepeatedFailedLoginsRule(threshold=5, window_seconds=60)],
        log_repository=log_repo,
        alert_repository=alert_repo,
        cooldown_seconds=60,
    )

    # Initial 5 failed logins
    for i in range(5):
        log_repo.add_log(
            create_log(
                client_id="attacker-burst",
                path="/api/login",
                status_code=401,
                method="POST",
                timestamp=now - timedelta(seconds=50 - i * 5),
            )
        )

    # First evaluation: triggers 1 alert
    alerts_1 = engine.evaluate_client("attacker-burst", current_time=now)
    assert len(alerts_1) == 1
    assert alert_repo.count_alerts() == 1

    # Attacker performs 3 more failed attempts 10 seconds later (within cooldown)
    for i in range(3):
        log_repo.add_log(
            create_log(
                client_id="attacker-burst",
                path="/api/login",
                status_code=401,
                method="POST",
                timestamp=now + timedelta(seconds=10 + i),
            )
        )

    # Second evaluation at now + 15s (within 60s cooldown): suppressed!
    alerts_2 = engine.evaluate_client(
        "attacker-burst", current_time=now + timedelta(seconds=15)
    )
    assert len(alerts_2) == 0
    assert alert_repo.count_alerts() == 1  # Still only 1 alert in storage

    # Now simulate time advancing past the cooldown window (e.g., now + 65 seconds)
    # Attacker continues failed attempts
    for i in range(5):
        log_repo.add_log(
            create_log(
                client_id="attacker-burst",
                path="/api/login",
                status_code=401,
                method="POST",
                timestamp=now + timedelta(seconds=61 + i),
            )
        )

    # Third evaluation after cooldown has expired: a new incident alert is created!
    alerts_3 = engine.evaluate_client(
        "attacker-burst", current_time=now + timedelta(seconds=66)
    )
    assert len(alerts_3) == 1
    assert alert_repo.count_alerts() == 2
