"""Tests for ML Anomaly Detection pipeline (Part 5).

Covers:
- Feature extraction and observation window filtering
- Data minimization (safe features only)
- Synthetic data generation and model training reproducibility
- AnomalyDetector loading and operational status
- Missing-model error handling (never fabricates predictions)
- Alert creation, evidence fields, and cooldown deduplication
- Distinctness between rule-based alerts and ML alerts
- Endpoints: GET /analysis/status and POST /analysis/run
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.timezone import IST, now_ist
from app.ml.detector import (
    DISCLAIMER_TEXT,
    AnomalyDetector,
    ModelNotFoundError,
    get_anomaly_detector,
    set_anomaly_detector,
)
from app.ml.features import (
    FEATURE_NAMES,
    ClientFeatures,
    extract_client_features,
    extract_features_for_all_clients,
)
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.log import RequestLog
from app.repositories.alert_repository import (
    InMemoryAlertRepository,
    get_alert_repository,
)
from app.repositories.log_repository import get_log_repository
from scripts.train_isolation_forest import (
    generate_synthetic_normal_data,
    train_model,
)


def make_log(
    client_id: str,
    path: str = "/api/products",
    status_code: int = 200,
    method: str = "GET",
    timestamp: datetime = None,
    process_time_ms: float = 2.0,
) -> RequestLog:
    """Helper to build RequestLog fixture."""
    return RequestLog(
        timestamp=timestamp or now_ist(),
        client_id=client_id,
        method=method,
        path=path,
        status_code=status_code,
        process_time_ms=process_time_ms,
    )


# ==============================================================================
# 1. Feature Extraction Tests
# ==============================================================================


def test_extract_client_features_normal_traffic() -> None:
    """Verify that normal browsing traffic computes expected feature values."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    logs = [
        make_log("client-1", "/api/products", 200, timestamp=now - timedelta(seconds=50)),
        make_log("client-1", "/api/products/1", 200, timestamp=now - timedelta(seconds=40)),
        make_log("client-1", "/health", 200, timestamp=now - timedelta(seconds=30)),
        make_log("client-1", "/", 200, timestamp=now - timedelta(seconds=20)),
    ]

    features = extract_client_features("client-1", logs, now, window_seconds=300)
    assert features.client_id == "client-1"
    assert features.observation_window_seconds == 300
    assert features.request_count == 4
    assert features.failed_login_count == 0
    assert features.error_4xx_proportion == 0.0
    assert features.distinct_paths_count == 4
    assert features.not_found_count == 0


def test_extract_client_features_failed_logins() -> None:
    """Verify that failed logins increment failed_login_count and error_4xx_proportion."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    logs = [
        make_log("client-2", "/api/login", 401, method="POST", timestamp=now - timedelta(seconds=10)),
        make_log("client-2", "/api/login", 401, method="POST", timestamp=now - timedelta(seconds=5)),
        make_log("client-2", "/api/products", 200, timestamp=now - timedelta(seconds=2)),
    ]

    features = extract_client_features("client-2", logs, now, window_seconds=300)
    assert features.request_count == 3
    assert features.failed_login_count == 2
    assert features.distinct_paths_count == 2
    assert features.not_found_count == 0
    assert features.error_4xx_proportion == round(2 / 3, 4)


def test_extract_client_features_404_probing() -> None:
    """Verify that 404 responses increment not_found_count and error_4xx_proportion."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    logs = [
        make_log("scanner", "/admin.php", 404, timestamp=now - timedelta(seconds=20)),
        make_log("scanner", "/.env", 404, timestamp=now - timedelta(seconds=15)),
        make_log("scanner", "/api/secret", 404, timestamp=now - timedelta(seconds=10)),
        make_log("scanner", "/api/products", 200, timestamp=now - timedelta(seconds=5)),
    ]

    features = extract_client_features("scanner", logs, now, window_seconds=300)
    assert features.request_count == 4
    assert features.distinct_paths_count == 4
    assert features.not_found_count == 3
    assert features.failed_login_count == 0
    assert features.error_4xx_proportion == 0.75


def test_extract_client_features_ignores_old_logs() -> None:
    """Logs older than window_seconds must be excluded from feature calculation."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    logs = [
        # Inside 300s window
        make_log("client-3", "/api/products", 200, timestamp=now - timedelta(seconds=100)),
        # Outside 300s window (350s ago)
        make_log("client-3", "/api/login", 401, method="POST", timestamp=now - timedelta(seconds=350)),
        make_log("client-3", "/missing", 404, timestamp=now - timedelta(seconds=400)),
    ]

    features = extract_client_features("client-3", logs, now, window_seconds=300)
    assert features.request_count == 1
    assert features.failed_login_count == 0
    assert features.not_found_count == 0
    assert features.error_4xx_proportion == 0.0


def test_extract_client_features_empty_logs() -> None:
    """Clients with zero logs in window should return zeroed features without division error."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    features = extract_client_features("empty-client", [], now, window_seconds=300)
    assert features.request_count == 0
    assert features.error_4xx_proportion == 0.0
    assert features.distinct_paths_count == 0
    vector = features.to_vector()
    assert vector == [0.0, 0.0, 0.0, 0.0, 0.0]


def test_extract_features_no_sensitive_data() -> None:
    """Ensure feature dictionary contains only numerical aggregations and client ID."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    logs = [make_log("client-safe", "/api/products", 200, timestamp=now)]
    features = extract_client_features("client-safe", logs, now)

    feat_dict = features.to_dict()
    assert set(feat_dict.keys()) == set(FEATURE_NAMES)
    for key in ["password", "token", "authorization", "body", "payload"]:
        assert key not in feat_dict


def test_extract_features_for_all_clients() -> None:
    """Verify grouping and feature extraction across multiple distinct clients."""
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    logs = [
        make_log("user-a", "/api/products", 200, timestamp=now - timedelta(seconds=10)),
        make_log("user-a", "/api/products/1", 200, timestamp=now - timedelta(seconds=5)),
        make_log("user-b", "/api/login", 401, method="POST", timestamp=now - timedelta(seconds=10)),
    ]

    all_features = extract_features_for_all_clients(logs, now, window_seconds=300)
    assert len(all_features) == 2
    assert "user-a" in all_features
    assert "user-b" in all_features
    assert all_features["user-a"].request_count == 2
    assert all_features["user-b"].request_count == 1
    assert all_features["user-b"].failed_login_count == 1


# ==============================================================================
# 2. Synthetic Data Generation & Training Tests
# ==============================================================================


def test_generate_synthetic_normal_data_shape_and_reproducibility() -> None:
    """Verify synthetic baseline generation produces consistent matrix."""
    data1 = generate_synthetic_normal_data(n_samples=500, random_state=42)
    data2 = generate_synthetic_normal_data(n_samples=500, random_state=42)

    assert data1.shape == (500, 5)
    np.testing.assert_array_equal(data1, data2)
    # Check that failed login counts are normal (mostly 0)
    assert np.mean(data1[:, 1]) < 0.1
    # Check that 4xx proportions are low (< 0.2)
    assert np.max(data1[:, 2]) <= 0.2


def test_train_model_produces_artifacts_and_metadata(tmp_path: Path) -> None:
    """Verify train_model saves valid joblib artifact and metadata file."""
    model, metadata = train_model(
        output_dir=str(tmp_path),
        n_samples=200,
        contamination=0.05,
        random_state=42,
        n_estimators=20,
    )

    model_file = tmp_path / "isolation_forest.joblib"
    meta_file = tmp_path / "model_metadata.json"

    assert model_file.exists()
    assert meta_file.exists()
    assert metadata["model_type"] == "IsolationForest"
    assert metadata["n_features"] == 5
    assert metadata["n_train_samples"] == 200
    assert metadata["disclaimer"] == DISCLAIMER_TEXT


# ==============================================================================
# 3. Model Loading & Operational Status Tests
# ==============================================================================


def test_anomaly_detector_loads_existing_model() -> None:
    """Verify that AnomalyDetector successfully loads the project model artifact."""
    detector = AnomalyDetector()
    assert detector.is_available() is True
    status = detector.get_status()
    assert status["model_available"] is True
    assert status["model_type"] == "IsolationForest"
    assert status["feature_names"] == FEATURE_NAMES
    assert "disclaimer" in status


def test_anomaly_detector_status_endpoint(client: TestClient) -> None:
    """Verify that GET /analysis/status reports model availability and metadata."""
    response = client.get("/analysis/status")
    assert response.status_code == 200
    data = response.json()
    assert data["model_available"] is True
    assert data["model_type"] == "IsolationForest"
    assert "feature_names" in data
    assert len(data["feature_names"]) == 5
    assert data["disclaimer"] == DISCLAIMER_TEXT


# ==============================================================================
# 4. Missing-Model Error Handling (Never Fabricates Predictions)
# ==============================================================================


def test_detector_handles_missing_model_gracefully() -> None:
    """Detector with non-existent path reports unavailable with setup instructions."""
    detector = AnomalyDetector(
        model_path="models/non_existent_model.joblib",
        metadata_path="models/non_existent_meta.json",
    )
    assert detector.is_available() is False
    status = detector.get_status()
    assert status["model_available"] is False
    assert "not found" in status["error"].lower()
    assert "setup_instructions" in status
    assert "python scripts/train_isolation_forest.py" in status["setup_instructions"]


def test_detector_predict_raises_on_missing_model() -> None:
    """Calling predict on missing model must raise ModelNotFoundError (no fabrication)."""
    detector = AnomalyDetector(
        model_path="models/does_not_exist.joblib",
        metadata_path="models/does_not_exist.json",
    )
    features = ClientFeatures(client_id="test", observation_window_seconds=300)

    with pytest.raises(ModelNotFoundError) as exc_info:
        detector.predict(features)
    assert "not available" in str(exc_info.value).lower()
    assert "python scripts/train_isolation_forest.py" in str(exc_info.value)


def test_analysis_run_endpoint_returns_503_when_model_missing(client: TestClient) -> None:
    """POST /analysis/run must return HTTP 503 when model is missing."""
    missing_detector = AnomalyDetector(
        model_path="models/missing_model_for_test.joblib",
        metadata_path="models/missing_meta_for_test.json",
    )
    set_anomaly_detector(missing_detector)

    response = client.post("/analysis/run")
    assert response.status_code == 503
    data = response.json()
    assert "not available" in data["detail"].lower()
    assert "python scripts/train_isolation_forest.py" in data["detail"]


# ==============================================================================
# 5. Prediction, Alert Creation & Cooldown Deduplication Tests
# ==============================================================================


def test_predict_normal_vs_anomalous_feature_vector() -> None:
    """Verify Isolation Forest correctly separates normal vs anomalous feature vectors."""
    detector = AnomalyDetector()

    # Normal user browsing catalog
    normal_features = ClientFeatures(
        client_id="normal-client",
        observation_window_seconds=300,
        request_count=12,
        failed_login_count=0,
        error_4xx_proportion=0.0,
        distinct_paths_count=3,
        not_found_count=0,
    )
    is_anomaly, score = detector.predict(normal_features)
    assert is_anomaly is False
    assert score > 0.0

    # Highly anomalous client (200 requests, 20 failed logins, 90% error rate, 25 paths, 15 404s)
    abnormal_features = ClientFeatures(
        client_id="attacker-client",
        observation_window_seconds=300,
        request_count=200,
        failed_login_count=20,
        error_4xx_proportion=0.90,
        distinct_paths_count=25,
        not_found_count=15,
    )
    is_anomaly, score = detector.predict(abnormal_features)
    assert is_anomaly is True
    assert score < 0.0


def test_create_anomaly_alert_contains_required_fields() -> None:
    """Verify generated ML alert contains rule_name, score, features, and disclaimer."""
    detector = AnomalyDetector()
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    features = ClientFeatures(
        client_id="anomaly-user",
        observation_window_seconds=300,
        request_count=150,
        failed_login_count=10,
        error_4xx_proportion=0.8,
        distinct_paths_count=20,
        not_found_count=12,
    )

    alert = detector.create_anomaly_alert(features, anomaly_score=-0.2154, current_time=now)
    assert alert.rule_name == "ML Anomaly Detection"
    assert alert.client_id == "anomaly-user"
    assert alert.severity == AlertSeverity.HIGH
    assert alert.status == AlertStatus.OPEN
    assert alert.evidence["source"] == "IsolationForest"
    assert alert.evidence["anomaly_score"] == -0.2154
    assert alert.evidence["features"]["request_count"] == 150
    assert alert.evidence["disclaimer"] == DISCLAIMER_TEXT


def test_rule_and_ml_alerts_are_distinguishable() -> None:
    """Rule-based alerts and ML alerts must have distinct rule names."""
    detector = AnomalyDetector()
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)
    features = ClientFeatures(
        client_id="test-client",
        observation_window_seconds=300,
        request_count=100,
    )

    ml_alert = detector.create_anomaly_alert(features, anomaly_score=-0.15, current_time=now)
    assert ml_alert.rule_name == "ML Anomaly Detection"

    # Known rule-based rule names
    rule_names = ["Repeated Failed Logins", "Request Burst", "Endpoint Probing"]
    assert ml_alert.rule_name not in rule_names


def test_ml_alert_cooldown_deduplication() -> None:
    """Engine must suppress duplicate ML alerts for same client during cooldown window."""
    detector = AnomalyDetector(cooldown_seconds=300)
    alert_repo = InMemoryAlertRepository()
    now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=IST)

    # Generate 50 anomalous requests for attacker
    logs = [
        make_log("abuser", f"/path-{i}", 404, timestamp=now - timedelta(seconds=i * 2))
        for i in range(50)
    ]

    # First analysis run: creates 1 ML alert
    report1 = detector.analyze_traffic(
        logs=logs,
        alert_repo=alert_repo,
        current_time=now,
    )
    assert report1["anomalies_detected"] == 1
    assert report1["alerts_created"] == 1
    assert alert_repo.count_alerts() == 1

    # Second analysis run 30 seconds later (within 300s cooldown): alert is suppressed!
    report2 = detector.analyze_traffic(
        logs=logs,
        alert_repo=alert_repo,
        current_time=now + timedelta(seconds=30),
    )
    assert report2["anomalies_detected"] == 1
    assert report2["alerts_created"] == 0
    assert report2["results"][0]["cooldown_suppressed"] is True
    assert alert_repo.count_alerts() == 1  # Still 1 alert

    # Third analysis run after cooldown (350s later) with continued anomalous activity: creates a new incident alert!
    later = now + timedelta(seconds=350)
    later_logs = logs + [
        make_log("abuser", f"/path-new-{i}", 404, timestamp=later - timedelta(seconds=i * 2))
        for i in range(50)
    ]
    report3 = detector.analyze_traffic(
        logs=later_logs,
        alert_repo=alert_repo,
        current_time=later,
    )
    assert report3["anomalies_detected"] == 1
    assert report3["alerts_created"] == 1
    assert alert_repo.count_alerts() == 2


# ==============================================================================
# 6. End-to-End API Analysis Endpoint Tests
# ==============================================================================


def test_analysis_run_endpoint_normal_traffic(client: TestClient) -> None:
    """Normal traffic generates 0 ML alerts during POST /analysis/run."""
    # Perform standard browsing requests
    for i in range(5):
        client.get("/api/products", headers={"X-Client-ID": "normal-browser"})

    response = client.post("/analysis/run")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["clients_analyzed"] >= 1
    assert data["anomalies_detected"] == 0
    assert data["alerts_created"] == 0
    assert data["disclaimer"] == DISCLAIMER_TEXT


def test_analysis_run_endpoint_anomalous_traffic(client: TestClient) -> None:
    """Anomalous probing traffic triggers ML alert retrievable via GET /alerts."""
    bad_actor = "aggressive-fuzzer"

    # Send 40 distinct 404 requests to simulate vulnerability scanner
    for i in range(40):
        client.get(f"/fuzz-target-{i}", headers={"X-Client-ID": bad_actor})

    response = client.post("/analysis/run?client_id=aggressive-fuzzer")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["anomalies_detected"] == 1
    assert data["alerts_created"] == 1
    assert data["results"][0]["client_id"] == bad_actor
    assert data["results"][0]["is_anomaly"] is True
    assert data["results"][0]["alert_id"] is not None

    # Verify that the generated alert is in the storage repository via GET /alerts
    alerts_res = client.get(f"/alerts?client_id={bad_actor}")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    # At least one alert with rule_name="ML Anomaly Detection"
    ml_alerts = [a for a in alerts if a["rule_name"] == "ML Anomaly Detection"]
    assert len(ml_alerts) == 1
    assert ml_alerts[0]["evidence"]["source"] == "IsolationForest"
    assert "anomaly_score" in ml_alerts[0]["evidence"]
    assert "features" in ml_alerts[0]["evidence"]
