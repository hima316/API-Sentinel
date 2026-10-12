"""Tests for MongoDB connection management, URI masking, and MongoDB repositories."""

import os
from unittest.mock import MagicMock, patch
import pytest
from pymongo.errors import ConnectionFailure, PyMongoError

from app.core.config import settings
from app.database.mongodb import (
    DatabaseConnectionError,
    DatabaseOperationError,
    MongoDBManager,
    mask_mongodb_uri,
)
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.log import RequestLog
from app.repositories.alert_repository import (
    InMemoryAlertRepository,
    MongoAlertRepository,
)
from app.repositories.log_repository import (
    InMemoryLogRepository,
    MongoLogRepository,
)


# ==============================================================================
# URI Masking & Security Tests
# ==============================================================================


def test_mask_mongodb_uri_standard() -> None:
    """Verify that credentials in standard mongodb:// URIs are masked."""
    raw_uri = "mongodb://myuser:supersecretpass@localhost:27017/api_sentinel"
    masked = mask_mongodb_uri(raw_uri)
    assert "supersecretpass" not in masked
    assert "myuser:****@" in masked
    assert "localhost:27017" in masked


def test_mask_mongodb_uri_srv() -> None:
    """Verify that credentials in mongodb+srv:// Atlas URIs are masked."""
    raw_uri = "mongodb+srv://atlasAdmin:P@ssw0rd123!@cluster0.abcde.mongodb.net/sentinel?retryWrites=true"
    masked = mask_mongodb_uri(raw_uri)
    assert "P@ssw0rd123!" not in masked
    assert "atlasAdmin:****@" in masked
    assert "cluster0.abcde.mongodb.net" in masked


def test_mask_mongodb_uri_empty_or_none() -> None:
    """Verify handling of empty or None URIs without errors."""
    assert mask_mongodb_uri(None) == "<unset>"
    assert mask_mongodb_uri("") == "<unset>"


# ==============================================================================
# Connection Error Handling & Diagnostics Tests
# ==============================================================================


def test_missing_uri_raises_connection_error() -> None:
    """Manager must raise DatabaseConnectionError when URI is explicitly passed as None."""
    manager = MongoDBManager(uri=None, database_name="test_db")
    with pytest.raises(DatabaseConnectionError) as exc_info:
        manager.get_client()
    assert "not configured" in str(exc_info.value).lower()


def test_empty_string_uri_raises_connection_error() -> None:
    """Manager must raise DatabaseConnectionError when URI is an empty string."""
    manager = MongoDBManager(uri="", database_name="test_db")
    with pytest.raises(DatabaseConnectionError) as exc_info:
        manager.get_client()
    assert "not configured" in str(exc_info.value).lower()


def test_placeholder_uri_raises_connection_error() -> None:
    """Manager must raise DatabaseConnectionError when URI contains template placeholders."""
    placeholder_uri = "mongodb+srv://<username>:<password>@cluster0.example.mongodb.net/?retryWrites=true&w=majority"
    manager = MongoDBManager(uri=placeholder_uri, database_name="test_db")
    with pytest.raises(DatabaseConnectionError) as exc_info:
        manager.get_client()
    assert "not configured" in str(exc_info.value).lower()


def test_default_unconfigured_uri_raises_connection_error() -> None:
    """Calling MongoDBManager() without arguments when unconfigured must raise error."""
    with patch("app.database.mongodb.settings.MONGODB_URI", ""):
        manager = MongoDBManager()
        with pytest.raises(DatabaseConnectionError) as exc_info:
            manager.get_client()
        assert "not configured" in str(exc_info.value).lower()


def test_unreachable_mongodb_server_raises_connection_error() -> None:
    """Connecting to an unreachable server must raise DatabaseConnectionError with masked URI."""
    secret_pass = "mySecretPassword99"
    unreachable_uri = (
        f"mongodb://admin:{secret_pass}@127.0.0.1:27999/test?"
        f"serverSelectionTimeoutMS=100&connectTimeoutMS=100"
    )

    manager = MongoDBManager(uri=unreachable_uri, database_name="test_db")
    with pytest.raises(DatabaseConnectionError) as exc_info:
        manager.get_client()

    err_msg = str(exc_info.value)
    # Password must never appear in error message
    assert secret_pass not in err_msg
    assert "admin:****@" in err_msg
    assert "failed to connect" in err_msg.lower()


# ==============================================================================
# Write Failure Handling (Do Not Silently Swallow Errors)
# ==============================================================================


def test_mongo_log_repository_write_failure_raises_error() -> None:
    """MongoLogRepository must raise DatabaseOperationError when insert fails."""
    mock_manager = MagicMock()
    mock_col = MagicMock()
    mock_manager.get_database.return_value.__getitem__.return_value = mock_col
    mock_col.insert_one.side_effect = PyMongoError("Simulated disk write failure")

    repo = MongoLogRepository(manager=mock_manager)
    log = RequestLog(
        client_id="client-test",
        method="GET",
        path="/api/products",
        status_code=200,
        process_time_ms=1.2,
    )

    with pytest.raises(DatabaseOperationError) as exc_info:
        repo.add_log(log)

    assert "failed to persist request log" in str(exc_info.value).lower()


def test_mongo_alert_repository_write_failure_raises_error() -> None:
    """MongoAlertRepository must raise DatabaseOperationError when insert fails."""
    mock_manager = MagicMock()
    mock_col = MagicMock()
    mock_manager.get_database.return_value.__getitem__.return_value = mock_col
    mock_col.insert_one.side_effect = PyMongoError("Simulated network timeout during write")

    repo = MongoAlertRepository(manager=mock_manager)
    alert = Alert(
        client_id="bad-actor",
        rule_name="Request Burst",
        severity=AlertSeverity.HIGH,
        reason="Burst detected",
        status=AlertStatus.OPEN,
    )

    with pytest.raises(DatabaseOperationError) as exc_info:
        repo.add_alert(alert)

    assert "failed to persist security alert" in str(exc_info.value).lower()


# ==============================================================================
# Live MongoDB Integration Tests (Conditional)
# Only executed when TEST_MONGODB_URI environment variable is provided.
# ==============================================================================


TEST_MONGODB_URI = os.getenv("TEST_MONGODB_URI")


@pytest.mark.skipif(
    not TEST_MONGODB_URI,
    reason="TEST_MONGODB_URI environment variable not set. Skipping live MongoDB tests.",
)
def test_live_mongo_log_repository_crud() -> None:
    """Integration test against live MongoDB instance (if configured)."""
    manager = MongoDBManager(uri=TEST_MONGODB_URI, database_name="sentinel_test_db")
    repo = MongoLogRepository(manager=manager)

    # Reset
    repo.clear_logs()
    assert repo.count_logs() == 0

    # Add logs
    log1 = RequestLog(client_id="live-user-1", method="GET", path="/api/products", status_code=200, process_time_ms=2.0)
    log2 = RequestLog(client_id="live-user-2", method="POST", path="/api/login", status_code=401, process_time_ms=1.5)
    repo.add_log(log1)
    repo.add_log(log2)

    assert repo.count_logs() == 2

    # Query newest first
    logs = repo.get_logs(limit=10)
    assert len(logs) == 2
    assert logs[0].client_id == "live-user-2"
    assert logs[1].client_id == "live-user-1"

    # Query by client
    client_logs = repo.get_logs_for_client("live-user-1")
    assert len(client_logs) == 1
    assert client_logs[0].path == "/api/products"

    # Cleanup
    repo.clear_logs()
    assert repo.count_logs() == 0
    manager.close()


@pytest.mark.skipif(
    not TEST_MONGODB_URI,
    reason="TEST_MONGODB_URI environment variable not set. Skipping live MongoDB tests.",
)
def test_live_mongo_alert_repository_crud() -> None:
    """Integration test against live MongoDB instance for alerts (if configured)."""
    manager = MongoDBManager(uri=TEST_MONGODB_URI, database_name="sentinel_test_db")
    repo = MongoAlertRepository(manager=manager)

    # Reset
    repo.clear_alerts()
    assert repo.count_alerts() == 0

    # Add alert
    alert = Alert(
        client_id="live-attacker",
        rule_name="Repeated Failed Logins",
        severity=AlertSeverity.HIGH,
        reason="Test alert in live Mongo",
        evidence={"failed_attempts": 5},
        status=AlertStatus.OPEN,
    )
    repo.add_alert(alert)
    assert repo.count_alerts() == 1

    # Get by ID
    fetched = repo.get_alert_by_id(alert.id)
    assert fetched is not None
    assert fetched.id == alert.id
    assert fetched.client_id == "live-attacker"

    # Get latest alert for rule
    latest = repo.get_latest_alert_for_rule("live-attacker", "Repeated Failed Logins")
    assert latest is not None
    assert latest.id == alert.id

    # Cleanup
    repo.clear_alerts()
    assert repo.count_alerts() == 0
    manager.close()
