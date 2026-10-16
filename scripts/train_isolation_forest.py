"""Synthetic training data generator and Isolation Forest model trainer.

This script generates synthetic baseline request telemetry representing normal API client
behavior, trains an Isolation Forest model with deterministic hyperparameters, and saves
the serialized model artifact and metadata to disk.

IMPORTANT DISCLAIMER:
Isolation Forest flags statistical deviations from training baselines, indicating unusual
behavior rather than confirmed malicious intent. Synthetic baseline training data does not
establish real-world accuracy. Training is kept strictly separate from runtime application startup.

Usage:
    python scripts/train_isolation_forest.py [--output-dir models] [--samples 1500] [--seed 42]
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, Tuple

IST = timezone(timedelta(hours=5, minutes=30), name="IST")

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_isolation_forest")

FEATURE_NAMES = [
    "request_count",
    "failed_login_count",
    "error_4xx_proportion",
    "distinct_paths_count",
    "not_found_count",
]

DISCLAIMER = (
    "Isolation Forest flags statistical deviations from training baselines, indicating unusual "
    "behavior rather than confirmed malicious intent. Synthetic baseline training data does "
    "not establish real-world accuracy."
)


def generate_synthetic_normal_data(
    n_samples: int = 1500,
    random_state: int = 42,
) -> np.ndarray:
    """Generate synthetic feature matrix representing normal, legitimate API traffic.

    Normal patterns over a 300-second (5-minute) observation window:
    - request_count: mostly 2 to 35 requests per client (browsing products, health checks).
    - failed_login_count: 0 for 98% of clients; occasionally 1 due to minor user typo.
    - error_4xx_proportion: mostly 0.0; occasionally 0.02 - 0.08 due to a single bad request.
    - distinct_paths_count: between 1 and 5 distinct endpoints.
    - not_found_count: 0 for 97% of clients; occasionally 1 due to a broken link.

    Args:
        n_samples: Number of synthetic training observation vectors to generate.
        random_state: Fixed random seed for reproducibility.

    Returns:
        np.ndarray of shape (n_samples, 5) with float values.
    """
    rng = np.random.default_rng(random_state)

    # 1. request_count: Poisson/Gamma centered around 12-18 requests, bounded [1, 40]
    raw_requests = rng.integers(low=2, high=35, size=n_samples)

    # 2. failed_login_count: 98% chance of 0, 2% chance of 1 (never high brute-force numbers)
    failed_logins = rng.choice([0, 1], size=n_samples, p=[0.98, 0.02])

    # 3. distinct_paths_count: 1 to 5 paths, bounded by request count
    distinct_paths = np.clip(
        rng.integers(low=1, high=6, size=n_samples),
        a_min=1,
        a_max=np.maximum(1, raw_requests),
    )

    # 4. not_found_count: 97% chance of 0, 3% chance of 1
    not_founds = rng.choice([0, 1], size=n_samples, p=[0.97, 0.03])

    # 5. error_4xx_proportion: calculated from total 4xx errors (failed logins + 404s + occasional 400)
    total_4xx = failed_logins + not_founds
    error_4xx_prop = np.round(np.clip(total_4xx / np.maximum(raw_requests, 1), 0.0, 0.20), 4)

    data = np.column_stack([
        raw_requests.astype(float),
        failed_logins.astype(float),
        error_4xx_prop.astype(float),
        distinct_paths.astype(float),
        not_founds.astype(float),
    ])

    return data


def train_model(
    output_dir: str = "models",
    n_samples: int = 1500,
    contamination: float = 0.05,
    random_state: int = 42,
    n_estimators: int = 100,
    observation_window_seconds: int = 300,
) -> Tuple[IsolationForest, Dict[str, Any]]:
    """Train Isolation Forest and persist model artifact and metadata to disk.

    Args:
        output_dir: Directory where model artifact and metadata will be saved.
        n_samples: Number of synthetic normal training samples.
        contamination: Expected proportion of outliers in the data.
        random_state: Fixed random seed.
        n_estimators: Number of base estimators (trees) in ensemble.
        observation_window_seconds: Window length in seconds represented by the features.

    Returns:
        Tuple of (trained IsolationForest model, metadata dictionary).
    """
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    logger.info("Generating %d synthetic normal baseline samples (seed=%d)...", n_samples, random_state)
    X_train = generate_synthetic_normal_data(n_samples=n_samples, random_state=random_state)

    logger.info(
        "Fitting IsolationForest(n_estimators=%d, contamination=%.2f, random_state=%d)...",
        n_estimators,
        contamination,
        random_state,
    )
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train)

    # Save model artifact
    model_file = out_path / "isolation_forest.joblib"
    joblib.dump(model, str(model_file))
    logger.info("Saved model artifact to %s", model_file)

    # Prepare and save metadata
    metadata = {
        "model_type": "IsolationForest",
        "algorithm": "sklearn.ensemble.IsolationForest",
        "version": "1.0.0",
        "created_at": datetime.now(IST).isoformat(),
        "feature_names": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "n_train_samples": n_samples,
        "contamination": contamination,
        "random_state": random_state,
        "n_estimators": n_estimators,
        "observation_window_seconds": observation_window_seconds,
        "disclaimer": DISCLAIMER,
    }

    metadata_file = out_path / "model_metadata.json"
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved model metadata to %s", metadata_file)

    # Quick validation sanity check
    normal_test = np.array([[12.0, 0.0, 0.0, 3.0, 0.0]])
    anomalous_test = np.array([[200.0, 15.0, 0.90, 25.0, 20.0]])

    normal_pred = model.predict(normal_test)[0]
    normal_score = model.decision_function(normal_test)[0]

    anomaly_pred = model.predict(anomalous_test)[0]
    anomaly_score = model.decision_function(anomalous_test)[0]

    logger.info(
        "Validation check:\n"
        "  Normal sample: pred=%d (1=normal), score=%.4f\n"
        "  Anomalous sample: pred=%d (-1=anomaly), score=%.4f",
        normal_pred,
        normal_score,
        anomaly_pred,
        anomaly_score,
    )

    return model, metadata


def main() -> None:
    """CLI entrypoint for training the Isolation Forest model."""
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest for API Sentinel anomaly detection."
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="models",
        help="Directory to save model artifacts (default: models)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1500,
        help="Number of synthetic normal samples to generate (default: 1500)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Contamination parameter (default: 0.05)",
    )

    args = parser.parse_args()
    train_model(
        output_dir=args.output_dir,
        n_samples=args.samples,
        contamination=args.contamination,
        random_state=args.seed,
    )


if __name__ == "__main__":
    main()
