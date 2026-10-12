"""Tests for Part 6: Traffic simulation and evaluation pipeline.

Covers:
- Binary classification metric computations and zero denominator safety
- Held-out test set generation and ground-truth labeling
- Offline evaluation of Rule-based, ML, and Combined detectors
- End-to-end traffic simulation against the local API (TestClient)
- Retrieval of simulated logs and alerts
- Live simulation evaluation and report generation
"""

from typing import Dict, List
import pytest
from fastapi.testclient import TestClient

from app.main import app
from scripts.evaluate_detection import (
    compute_binary_metrics,
    evaluate_held_out_dataset,
    evaluate_live_simulation,
    generate_held_out_test_set,
)
from scripts.simulate_traffic import simulate_all_scenarios


# ==============================================================================
# 1. Metrics Computation & Zero Denominator Tests
# ==============================================================================


def test_compute_binary_metrics_perfect_classifier() -> None:
    """Perfect predictions should yield precision=1.0, recall=1.0, f1=1.0, fpr=0.0."""
    y_true = [1, 1, 0, 0]
    y_pred = [1, 1, 0, 0]

    metrics = compute_binary_metrics(y_true, y_pred, name="PerfectModel")
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1_score"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["confusion_matrix"]["true_positives"] == 2
    assert metrics["confusion_matrix"]["true_negatives"] == 2
    assert metrics["confusion_matrix"]["false_positives"] == 0
    assert metrics["confusion_matrix"]["false_negatives"] == 0


def test_compute_binary_metrics_zero_denominators_safety() -> None:
    """Zero denominator cases (e.g. no positive predictions or true positives) must not raise."""
    # Case A: Model predicts only negatives -> TP + FP = 0
    y_true = [1, 0, 0]
    y_pred = [0, 0, 0]
    metrics_a = compute_binary_metrics(y_true, y_pred)
    assert metrics_a["precision"] == 0.0
    assert metrics_a["recall"] == 0.0
    assert metrics_a["f1_score"] == 0.0
    assert metrics_a["false_positive_rate"] == 0.0

    # Case B: Dataset contains only positive samples -> FP + TN = 0
    y_true_b = [1, 1]
    y_pred_b = [1, 1]
    metrics_b = compute_binary_metrics(y_true_b, y_pred_b)
    assert metrics_b["false_positive_rate"] == 0.0


def test_compute_binary_metrics_mismatched_lengths_raises() -> None:
    """Mismatched array lengths should raise ValueError."""
    with pytest.raises(ValueError) as exc:
        compute_binary_metrics([1, 0], [1])
    assert "identical length" in str(exc.value)


# ==============================================================================
# 2. Held-Out Dataset & Evaluation Tests
# ==============================================================================


def test_generate_held_out_test_set_structure() -> None:
    """Verify held-out generator produces expected sample counts and valid labels."""
    features, labels = generate_held_out_test_set(n_normal=100, n_attack=40, random_state=2026)
    assert len(features) == 140
    assert len(labels) == 140
    assert sum(1 for y in labels if y == 0) == 100
    assert sum(1 for y in labels if y == 1) == 40

    # Verify features are populated and positive
    for feat in features:
        assert feat.request_count >= 0
        assert 0.0 <= feat.error_4xx_proportion <= 1.0
        assert feat.observation_window_seconds == 300


def test_evaluate_held_out_dataset_returns_all_detectors() -> None:
    """Verify evaluate_held_out_dataset evaluates Rule, ML, and Combined detectors separately."""
    result = evaluate_held_out_dataset(n_normal=100, n_attack=40, seed=2026)
    assert "detectors" in result
    detectors = result["detectors"]

    assert "rule_based" in detectors
    assert "ml_isolation_forest" in detectors
    assert "combined_hybrid" in detectors

    # Rule-based detector should have 0 false positives on normal baseline
    assert detectors["rule_based"]["confusion_matrix"]["false_positives"] == 0
    assert detectors["rule_based"]["precision"] == 1.0

    # Combined hybrid detector should achieve high recall
    assert detectors["combined_hybrid"]["recall"] >= 0.90
    assert "disclaimer" in result


# ==============================================================================
# 3. Live Simulation & Evaluation Workflow Tests
# ==============================================================================


def test_live_simulation_workflow_against_api(client: TestClient) -> None:
    """End-to-end: run simulated traffic against API, verify log/alert retrieval and evaluation."""
    # 1. Run simulated traffic scenarios against TestClient
    manifest = simulate_all_scenarios(client=client, delay=0.0)
    assert manifest["total_clients"] == 6
    assert manifest["total_requests"] >= 70
    assert manifest["normal_clients_count"] == 2
    assert manifest["malicious_clients_count"] == 4

    # 2. Confirm request logs were captured
    logs_res = client.get("/logs?limit=100")
    assert logs_res.status_code == 200
    logs = logs_res.json()
    assert len(logs) >= 70

    # 3. Confirm rule alerts were generated during simulation
    alerts_res = client.get("/alerts?limit=100")
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) > 0

    # Verify rule alerts for specific malicious clients
    brute_alerts = [a for a in alerts if a["client_id"] == "client-brute-force"]
    assert len(brute_alerts) >= 1
    assert brute_alerts[0]["rule_name"] == "Repeated Failed Logins"

    probing_alerts = [a for a in alerts if a["client_id"] == "client-endpoint-probing"]
    assert len(probing_alerts) >= 1
    assert probing_alerts[0]["rule_name"] == "Endpoint Probing"

    burst_alerts = [a for a in alerts if a["client_id"] == "client-request-burst"]
    assert len(burst_alerts) >= 1
    assert burst_alerts[0]["rule_name"] == "Request Burst"

    # Verify normal clients did not generate any rule alerts
    normal_alerts = [a for a in alerts if "normal" in a["client_id"]]
    assert len(normal_alerts) == 0

    # 4. Run evaluation against the simulation manifest
    eval_results = evaluate_live_simulation(manifest=manifest, client=client)
    assert "detectors" in eval_results
    detectors = eval_results["detectors"]

    # Rule-based detector correctly flagged attacks without flagging normal clients
    assert detectors["rule_based"]["confusion_matrix"]["true_positives"] >= 3
    assert detectors["rule_based"]["confusion_matrix"]["false_positives"] == 0
    assert detectors["rule_based"]["precision"] == 1.0

    # ML detector evaluated
    assert detectors["ml_isolation_forest"]["total_samples"] == 6

    # Combined hybrid detector evaluated
    assert detectors["combined_hybrid"]["total_samples"] == 6
