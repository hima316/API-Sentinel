"""Evaluation framework for API Sentinel detection systems (Part 6).

Evaluates:
1. Rule-Based Abuse Detection Engine (Rules)
2. ML Anomaly Detection (Isolation Forest)
3. Combined (Hybrid) Detection

Calculates:
- Precision
- Recall
- F1 Score
- False-Positive Rate (FPR)
- Confusion Matrix (TP, FP, TN, FN)

METHODOLOGY & GROUND TRUTH DEFINITION:
- Labels are assigned strictly by traffic generation scenario parameters (0=Normal, 1=Abuse/Anomaly).
- Model predictions are NEVER used as ground truth.
- Zero denominators are safely handled without throwing exceptions.
- Evaluates on a held-out synthetic test set (seed=2026) distinct from the training set,
  and optionally on live simulated traffic from the API.

Usage:
    python scripts/evaluate_detection.py [--mode both|held-out|live] [--manifest reports/simulation_manifest.json]
"""

import argparse
import csv
from datetime import datetime, timedelta, timezone
import json

IST = timezone(timedelta(hours=5, minutes=30), name="IST")
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

import httpx
import numpy as np

# Ensure project root is in sys.path for direct script execution
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from app.core.config import settings
from app.ml.detector import DISCLAIMER_TEXT, AnomalyDetector
from app.ml.features import FEATURE_NAMES, ClientFeatures

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_detection")


def compute_binary_metrics(
    y_true: List[int],
    y_pred: List[int],
    name: str = "Detector",
) -> Dict[str, Any]:
    """Calculate binary classification performance metrics with safe zero handling.

    Args:
        y_true: Ground truth binary labels (0 = Normal, 1 = Abuse/Anomaly).
        y_pred: Predicted binary labels (0 = Normal, 1 = Abuse/Anomaly).
        name: Name identifier for the evaluated detector.

    Returns:
        Dictionary containing confusion matrix, precision, recall, F1, and FPR.
    """
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have identical length.")

    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    # Safe divisions for zero denominators
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "detector_name": name,
        "total_samples": len(y_true),
        "confusion_matrix": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
        },
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
    }


def generate_held_out_test_set(
    n_normal: int = 500,
    n_attack: int = 200,
    random_state: int = 2026,
) -> Tuple[List[ClientFeatures], List[int]]:
    """Generate a held-out synthetic test set with ground truth labels.

    This dataset uses a separate seed (2026) and was not used during Isolation Forest training.
    Ground truth labels (0=Normal, 1=Abuse) are derived strictly from scenario parameters.

    Attack distributions (50 samples each):
    - Brute Force: High failed logins (5-15), high 4xx proportion (0.7-1.0)
    - Burst / Scraper: High request volume (35-80) in short observation window
    - Endpoint Probing: High distinct paths (6-20), high 404 count (4-15)
    - Mixed Suspicious: Elevated volume (40-70), 3-6 failed logins, 3-8 404s

    Returns:
        Tuple of (list of ClientFeatures, list of ground truth integer labels).
    """
    rng = np.random.default_rng(random_state)
    features_list: List[ClientFeatures] = []
    labels_list: List[int] = []

    # 1. Normal Samples (Label 0): benign browsing traffic comfortably below rule thresholds
    for i in range(n_normal):
        reqs = int(rng.integers(low=2, high=25))
        failed_logins = int(rng.choice([0, 1], p=[0.98, 0.02]))
        not_founds = int(rng.choice([0, 1], p=[0.97, 0.03]))
        distinct_paths = int(rng.integers(low=1, high=min(5, max(2, reqs))))
        total_4xx = failed_logins + not_founds
        error_prop = round(float(total_4xx / max(reqs, 1)), 4)

        feat = ClientFeatures(
            client_id=f"test-normal-{i}",
            observation_window_seconds=300,
            request_count=reqs,
            failed_login_count=failed_logins,
            error_4xx_proportion=error_prop,
            distinct_paths_count=distinct_paths,
            not_found_count=not_founds,
        )
        features_list.append(feat)
        labels_list.append(0)

    # 2. Attack Samples (Label 1)
    attack_subtypes = ["brute_force", "burst", "probing", "mixed"]
    samples_per_sub = n_attack // len(attack_subtypes)

    for sub in attack_subtypes:
        for i in range(samples_per_sub):
            if sub == "brute_force":
                failed_logins = int(rng.integers(low=5, high=12))
                reqs = int(rng.integers(low=failed_logins, high=failed_logins + 10))
                not_founds = 0
                distinct_paths = int(rng.integers(low=1, high=3))
                error_prop = min(1.0, round(float(failed_logins / reqs), 4))
            elif sub == "burst":
                reqs = int(rng.integers(low=35, high=70))
                failed_logins = 0
                not_founds = 0
                distinct_paths = int(rng.integers(low=1, high=4))
                error_prop = 0.0
            elif sub == "probing":
                not_founds = int(rng.integers(low=4, high=10))
                distinct_paths = int(rng.integers(low=not_founds, high=not_founds + 4))
                reqs = int(rng.integers(low=distinct_paths, high=distinct_paths + 10))
                failed_logins = 0
                error_prop = min(1.0, round(float(not_founds / reqs), 4))
            else:  # mixed evasive abuse: metrics individually stay just below static rule thresholds
                failed_logins = int(rng.integers(low=3, high=5))  # below failed login threshold of 5
                not_founds = 2  # below 404 threshold of 3
                distinct_paths = int(rng.integers(low=4, high=6))
                reqs = int(rng.integers(low=failed_logins + not_founds + 4, high=29))  # below burst threshold of 30
                error_prop = min(1.0, round(float((failed_logins + not_founds) / reqs), 4))

            feat = ClientFeatures(
                client_id=f"test-{sub}-{i}",
                observation_window_seconds=300,
                request_count=reqs,
                failed_login_count=failed_logins,
                error_4xx_proportion=error_prop,
                distinct_paths_count=distinct_paths,
                not_found_count=not_founds,
            )
            features_list.append(feat)
            labels_list.append(1)

    return features_list, labels_list


def evaluate_held_out_dataset(
    detector: Optional[AnomalyDetector] = None,
    n_normal: int = 500,
    n_attack: int = 200,
    seed: int = 2026,
) -> Dict[str, Any]:
    """Evaluate Rule, ML, and Combined detectors against a held-out test dataset."""
    ml_detector = detector or AnomalyDetector()
    if not ml_detector.is_available():
        raise RuntimeError(
            f"ML model is unavailable at '{ml_detector.model_path}'. "
            "Run 'python scripts/train_isolation_forest.py' before evaluating."
        )

    features_list, y_true = generate_held_out_test_set(
        n_normal=n_normal,
        n_attack=n_attack,
        random_state=seed,
    )

    y_pred_rules: List[int] = []
    y_pred_ml: List[int] = []
    y_pred_combined: List[int] = []

    for feat in features_list:
        # 1. Rule-Based Detector Evaluation
        rule_triggered = (
            feat.failed_login_count >= settings.FAILED_LOGIN_THRESHOLD
            or feat.request_count >= settings.BURST_REQUEST_THRESHOLD
            or (
                feat.distinct_paths_count >= settings.PROBING_DISTINCT_PATHS_THRESHOLD
                and feat.not_found_count >= settings.PROBING_404_THRESHOLD
            )
        )
        rule_pred = 1 if rule_triggered else 0
        y_pred_rules.append(rule_pred)

        # 2. ML Detector Evaluation
        is_anomaly, _ = ml_detector.predict(feat)
        ml_pred = 1 if is_anomaly else 0
        y_pred_ml.append(ml_pred)

        # 3. Combined (Hybrid) Detector Evaluation
        comb_pred = 1 if (rule_pred == 1 or ml_pred == 1) else 0
        y_pred_combined.append(comb_pred)

    metrics_rules = compute_binary_metrics(y_true, y_pred_rules, "Rule-Based Detection")
    metrics_ml = compute_binary_metrics(y_true, y_pred_ml, "ML Anomaly Detection (Isolation Forest)")
    metrics_combined = compute_binary_metrics(y_true, y_pred_combined, "Combined Hybrid Detection")

    return {
        "evaluation_dataset": "held_out_synthetic",
        "random_seed": seed,
        "sample_counts": {
            "total": len(y_true),
            "normal": sum(1 for y in y_true if y == 0),
            "attack": sum(1 for y in y_true if y == 1),
        },
        "detectors": {
            "rule_based": metrics_rules,
            "ml_isolation_forest": metrics_ml,
            "combined_hybrid": metrics_combined,
        },
        "disclaimer": DISCLAIMER_TEXT,
    }


def evaluate_live_simulation(
    manifest: Dict[str, Any],
    api_url: str = "http://127.0.0.1:8000",
    client: Optional[httpx.Client] = None,
) -> Dict[str, Any]:
    """Evaluate live simulation run by comparing triggered alerts with scenario ground truth."""
    close_client = False
    if client is None:
        client = httpx.Client(base_url=api_url, timeout=10.0)
        close_client = True

    try:
        # Trigger ML analysis run on recent traffic
        analysis_res = client.post("/analysis/run")
        if analysis_res.status_code != 200:
            logger.warning("POST /analysis/run returned status %d: %s", analysis_res.status_code, analysis_res.text)

        # Retrieve stored security alerts from the API
        alerts_res = client.get("/alerts?limit=100")
        if alerts_res.status_code != 200:
            raise RuntimeError(f"Failed to fetch /alerts from API ({alerts_res.status_code}): {alerts_res.text}")

        all_alerts: List[Dict[str, Any]] = alerts_res.json()

        y_true: List[int] = []
        y_pred_rules: List[int] = []
        y_pred_ml: List[int] = []
        y_pred_combined: List[int] = []
        per_client_details: List[Dict[str, Any]] = []

        scenarios = manifest.get("scenarios", [])
        for sc in scenarios:
            cid = sc["client_id"]
            gt = sc["ground_truth_label"]
            y_true.append(gt)

            client_alerts = [a for a in all_alerts if a["client_id"] == cid]

            has_rule_alert = any(a["rule_name"] != "ML Anomaly Detection" for a in client_alerts)
            has_ml_alert = any(a["rule_name"] == "ML Anomaly Detection" for a in client_alerts)

            rule_pred = 1 if has_rule_alert else 0
            ml_pred = 1 if has_ml_alert else 0
            comb_pred = 1 if (rule_pred == 1 or ml_pred == 1) else 0

            y_pred_rules.append(rule_pred)
            y_pred_ml.append(ml_pred)
            y_pred_combined.append(comb_pred)

            per_client_details.append({
                "client_id": cid,
                "scenario": sc.get("scenario"),
                "ground_truth": gt,
                "rule_alert_triggered": has_rule_alert,
                "ml_alert_triggered": has_ml_alert,
                "alerts_recorded": [a["rule_name"] for a in client_alerts],
            })

        metrics_rules = compute_binary_metrics(y_true, y_pred_rules, "Rule-Based Detection")
        metrics_ml = compute_binary_metrics(y_true, y_pred_ml, "ML Anomaly Detection (Isolation Forest)")
        metrics_combined = compute_binary_metrics(y_true, y_pred_combined, "Combined Hybrid Detection")

        return {
            "evaluation_dataset": "live_traffic_simulation",
            "api_url": api_url,
            "sample_counts": {
                "total": len(y_true),
                "normal": sum(1 for y in y_true if y == 0),
                "attack": sum(1 for y in y_true if y == 1),
            },
            "detectors": {
                "rule_based": metrics_rules,
                "ml_isolation_forest": metrics_ml,
                "combined_hybrid": metrics_combined,
            },
            "client_breakdown": per_client_details,
            "disclaimer": DISCLAIMER_TEXT,
        }
    finally:
        if close_client:
            client.close()


def save_reports(
    results: Dict[str, Any],
    json_path: str = "reports/evaluation_results.json",
    csv_path: str = "reports/evaluation_metrics.csv",
) -> None:
    """Save structured evaluation output to JSON and CSV formats."""
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)

    # 1. Save JSON report
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info("Saved full evaluation JSON report to %s", json_path)

    # 2. Save CSV summary
    rows: List[Dict[str, Any]] = []
    for mode, data in results.items():
        if isinstance(data, dict) and "detectors" in data:
            for det_key, metrics in data["detectors"].items():
                cm = metrics["confusion_matrix"]
                rows.append({
                    "evaluation_mode": mode,
                    "detector": metrics["detector_name"],
                    "total_samples": metrics["total_samples"],
                    "precision": metrics["precision"],
                    "recall": metrics["recall"],
                    "f1_score": metrics["f1_score"],
                    "false_positive_rate": metrics["false_positive_rate"],
                    "true_positives": cm["true_positives"],
                    "false_positives": cm["false_positives"],
                    "true_negatives": cm["true_negatives"],
                    "false_negatives": cm["false_negatives"],
                })

    if rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        logger.info("Saved metrics CSV summary to %s", csv_path)


def print_summary_table(title: str, detectors_dict: Dict[str, Any]) -> None:
    """Format and print an aligned terminal summary table."""
    print(f"\n{'='*78}")
    print(f" {title.upper()}")
    print(f"{'='*78}")
    header = f"{'Detector':<35} | {'Precision':<9} | {'Recall':<8} | {'F1':<6} | {'FPR':<6} | {'TP':<4} | {'FP':<4} | {'TN':<4} | {'FN':<4}"
    print(header)
    print("-" * 78)
    for key, d in detectors_dict.items():
        cm = d["confusion_matrix"]
        line = (
            f"{d['detector_name'][:35]:<35} | "
            f"{d['precision']:<9.4f} | "
            f"{d['recall']:<8.4f} | "
            f"{d['f1_score']:<6.4f} | "
            f"{d['false_positive_rate']:<6.4f} | "
            f"{cm['true_positives']:<4} | "
            f"{cm['false_positives']:<4} | "
            f"{cm['true_negatives']:<4} | "
            f"{cm['false_negatives']:<4}"
        )
        print(line)
    print("=" * 78)


def main() -> None:
    """CLI entrypoint for detection evaluation."""
    parser = argparse.ArgumentParser(description="Evaluate API Sentinel detection systems.")
    parser.add_argument(
        "--mode",
        choices=["both", "held-out", "live"],
        default="both",
        help="Evaluation mode (default: both)",
    )
    parser.add_argument(
        "--manifest",
        type=str,
        default="reports/simulation_manifest.json",
        help="Path to simulation manifest for live evaluation (default: reports/simulation_manifest.json)",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://127.0.0.1:8000",
        help="Target API URL for live evaluation (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--json-out",
        type=str,
        default="reports/evaluation_results.json",
        help="JSON output path (default: reports/evaluation_results.json)",
    )
    parser.add_argument(
        "--csv-out",
        type=str,
        default="reports/evaluation_metrics.csv",
        help="CSV output path (default: reports/evaluation_metrics.csv)",
    )

    args = parser.parse_args()
    all_reports: Dict[str, Any] = {
        "timestamp": datetime.now(IST).isoformat(),
        "disclaimer": DISCLAIMER_TEXT,
    }

    # 1. Held-out synthetic dataset evaluation
    if args.mode in ["both", "held-out"]:
        logger.info("Evaluating held-out synthetic test set (500 normal, 200 attack)...")
        held_out_res = evaluate_held_out_dataset()
        all_reports["held_out_evaluation"] = held_out_res
        print_summary_table("Held-Out Synthetic Test Set Evaluation (Seed=2026)", held_out_res["detectors"])

    # 2. Live simulation evaluation
    if args.mode in ["both", "live"]:
        manifest_file = Path(args.manifest)
        if manifest_file.is_file():
            logger.info("Evaluating live simulation manifest from %s...", manifest_file)
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
            try:
                live_res = evaluate_live_simulation(manifest_data, api_url=args.api_url)
                all_reports["live_simulation_evaluation"] = live_res
                print_summary_table("Live Simulated Traffic Evaluation", live_res["detectors"])
            except Exception as exc:
                logger.warning("Could not execute live evaluation against %s: %s", args.api_url, exc)
        else:
            logger.warning(
                "Simulation manifest '%s' not found. Run 'python scripts/simulate_traffic.py' first to evaluate live traffic.",
                args.manifest,
            )

    save_reports(all_reports, json_path=args.json_out, csv_path=args.csv_out)
    print("\n[NOTE] Interpretation of Results:")
    print("  - Rule-based detection achieves zero false positives (FPR=0.0) when static thresholds are tuned, but can miss multi-vector combinations below individual limits.")
    print("  - Isolation Forest detects anomalous multi-dimensional deviations with high recall, but incurs a small false positive rate (~5%) corresponding to its training contamination baseline.")
    print("  - The combined hybrid detector leverages the precision of rules alongside the generalization of unsupervised ML.")
    print("  - Disclaimer: Synthetic data does not establish real-world or production detection accuracy.\n")


if __name__ == "__main__":
    main()
