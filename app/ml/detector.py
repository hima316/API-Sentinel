"""Machine learning anomaly detector using scikit-learn Isolation Forest.

Provides model loading, feature scoring, threshold evaluation, and alert creation.
Preserves strict safety: does not fabricate predictions or silently skip analysis if the model is missing.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Tuple

import joblib

from app.core.config import settings
from app.core.timezone import IST, now_ist
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.log import RequestLog
from app.ml.features import (
    FEATURE_NAMES,
    ClientFeatures,
    extract_client_features,
    extract_features_for_all_clients,
)
from app.repositories.alert_repository import BaseAlertRepository

logger = logging.getLogger("api_sentinel.ml")

DISCLAIMER_TEXT = (
    "Isolation Forest flags statistical deviations from training baselines, indicating unusual "
    "behavior rather than confirmed malicious intent. Synthetic baseline training data does "
    "not establish real-world accuracy."
)


class MLModelError(Exception):
    """Base exception for ML model errors."""

    pass


class ModelNotFoundError(MLModelError):
    """Raised when the trained model artifact cannot be found or loaded."""

    pass


class AnomalyDetector:
    """Evaluates client feature vectors against a trained Isolation Forest model."""

    RULE_NAME: str = "ML Anomaly Detection"

    def __init__(
        self,
        model_path: Optional[str] = None,
        metadata_path: Optional[str] = None,
        observation_window_seconds: Optional[int] = None,
        cooldown_seconds: Optional[int] = None,
    ) -> None:
        """Initialize detector with paths and configuration."""
        self.model_path = model_path or settings.ML_MODEL_PATH
        self.metadata_path = metadata_path or settings.ML_METADATA_PATH
        self.observation_window_seconds = (
            observation_window_seconds
            if observation_window_seconds is not None
            else settings.ML_OBSERVATION_WINDOW_SECONDS
        )
        self.cooldown_seconds = (
            cooldown_seconds
            if cooldown_seconds is not None
            else settings.ML_ALERT_COOLDOWN_SECONDS
        )

        self._lock = threading.Lock()
        self._model: Optional[Any] = None
        self._metadata: Optional[Dict[str, Any]] = None
        self._loaded: bool = False
        self._load_error: Optional[str] = None

        # Attempt initial load
        self.load_model()

    def load_model(self) -> bool:
        """Attempt to load the model file and metadata from disk.

        Returns:
            True if model successfully loaded, False otherwise.
        """
        with self._lock:
            self._model = None
            self._metadata = None
            self._loaded = False
            self._load_error = None

            model_file = Path(self.model_path)
            metadata_file = Path(self.metadata_path)

            if not model_file.is_file():
                self._load_error = (
                    f"Model file not found at '{self.model_path}'. "
                    "Run 'python scripts/train_isolation_forest.py' to train and save the model."
                )
                logger.warning(self._load_error)
                return False

            try:
                self._model = joblib.load(str(model_file))
            except Exception as exc:
                self._load_error = f"Failed to load model file '{self.model_path}': {str(exc)}"
                logger.error(self._load_error)
                return False

            # Load optional metadata if available
            if metadata_file.is_file():
                try:
                    with open(metadata_file, "r", encoding="utf-8") as f:
                        self._metadata = json.load(f)
                except Exception as exc:
                    logger.warning("Could not parse metadata file '%s': %s", self.metadata_path, exc)
                    self._metadata = None
            else:
                self._metadata = {
                    "model_type": "IsolationForest",
                    "feature_names": FEATURE_NAMES,
                    "observation_window_seconds": self.observation_window_seconds,
                    "disclaimer": DISCLAIMER_TEXT,
                }

            self._loaded = True
            logger.info("Successfully loaded ML anomaly detection model from %s", self.model_path)
            return True

    def is_available(self) -> bool:
        """Check if the model is currently loaded and ready for inference."""
        with self._lock:
            return self._loaded and self._model is not None

    @property
    def feature_names(self) -> List[str]:
        """Return the feature names expected by the model."""
        if self._metadata and "feature_names" in self._metadata:
            return self._metadata["feature_names"]
        return FEATURE_NAMES

    def get_status(self) -> Dict[str, Any]:
        """Return a structured status report regarding model availability."""
        with self._lock:
            if not self._loaded or self._model is None:
                return {
                    "model_available": False,
                    "model_path": self.model_path,
                    "metadata_path": self.metadata_path,
                    "error": self._load_error or "Model is not loaded.",
                    "setup_instructions": (
                        "Run 'python scripts/train_isolation_forest.py' to generate synthetic "
                        "baseline data and train the Isolation Forest model."
                    ),
                    "disclaimer": DISCLAIMER_TEXT,
                }

            meta = self._metadata or {}
            return {
                "model_available": True,
                "model_path": self.model_path,
                "metadata_path": self.metadata_path,
                "model_type": meta.get("model_type", "IsolationForest"),
                "version": meta.get("version", "1.0.0"),
                "observation_window_seconds": meta.get(
                    "observation_window_seconds", self.observation_window_seconds
                ),
                "feature_names": self.feature_names,
                "contamination": meta.get("contamination", settings.ML_CONTAMINATION),
                "random_state": meta.get("random_state", settings.ML_RANDOM_STATE),
                "created_at": meta.get("created_at"),
                "disclaimer": meta.get("disclaimer", DISCLAIMER_TEXT),
            }

    def predict(self, features: ClientFeatures) -> Tuple[bool, float]:
        """Run Isolation Forest inference on a client's feature vector.

        Args:
            features: Calculated client metrics.

        Returns:
            Tuple of (is_anomaly: bool, anomaly_score: float).
            Higher score indicates normality; negative score indicates anomaly.

        Raises:
            ModelNotFoundError: If the model is not loaded. Never fabricates predictions.
        """
        with self._lock:
            if not self._loaded or self._model is None:
                raise ModelNotFoundError(
                    f"ML model is not available at '{self.model_path}'. "
                    "Run 'python scripts/train_isolation_forest.py' to train and save the model before running analysis."
                )

            vector = features.to_vector(self.feature_names)
            prediction = self._model.predict([vector])[0]
            # IsolationForest decision_function: < 0 is anomaly, >= 0 is inlier
            raw_score = float(self._model.decision_function([vector])[0])

            is_anomaly = bool(prediction == -1)
            return is_anomaly, round(raw_score, 4)

    def create_anomaly_alert(
        self,
        features: ClientFeatures,
        anomaly_score: float,
        current_time: datetime,
    ) -> Alert:
        """Create an Alert instance for a detected anomaly."""
        severity = AlertSeverity.HIGH if anomaly_score < -0.1 else AlertSeverity.MEDIUM

        reason = (
            f"Isolation Forest flagged statistically anomalous behavior for client "
            f"'{features.client_id}' (anomaly score: {anomaly_score}) over "
            f"{features.observation_window_seconds}s observation window."
        )

        evidence = {
            "source": "IsolationForest",
            "anomaly_score": anomaly_score,
            "observation_window_seconds": features.observation_window_seconds,
            "features": features.to_dict(),
            "disclaimer": DISCLAIMER_TEXT,
        }

        return Alert(
            timestamp=current_time,
            client_id=features.client_id,
            rule_name=self.RULE_NAME,
            severity=severity,
            reason=reason,
            evidence=evidence,
            status=AlertStatus.OPEN,
        )

    def analyze_traffic(
        self,
        logs: List[RequestLog],
        alert_repo: BaseAlertRepository,
        current_time: Optional[datetime] = None,
        cooldown_seconds: Optional[int] = None,
        target_client_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Analyze recent traffic, evaluate Isolation Forest, and persist non-duplicate alerts.

        Args:
            logs: Recent request log entries from storage.
            alert_repo: Repository to store alerts and query for deduplication.
            current_time: Reference time for observation window (defaults to now IST).
            cooldown_seconds: Minimum time between successive ML alerts for the same client.
            target_client_id: If specified, analyze only this client; otherwise all active clients.

        Returns:
            Structured summary of evaluated clients and generated alerts.

        Raises:
            ModelNotFoundError: If model is not loaded. Never silently skips analysis.
        """
        now = current_time or now_ist()
        cooldown = cooldown_seconds if cooldown_seconds is not None else self.cooldown_seconds

        if not self.is_available():
            raise ModelNotFoundError(
                f"ML model is not available at '{self.model_path}'. "
                "Run 'python scripts/train_isolation_forest.py' to train and save the model before running analysis."
            )

        if target_client_id:
            client_features_map = {
                target_client_id: extract_client_features(
                    client_id=target_client_id,
                    logs=logs,
                    current_time=now,
                    window_seconds=self.observation_window_seconds,
                )
            }
        else:
            client_features_map = extract_features_for_all_clients(
                logs=logs,
                current_time=now,
                window_seconds=self.observation_window_seconds,
            )

        results: List[Dict[str, Any]] = []
        alerts_created_count = 0
        anomalies_detected_count = 0

        for client_id, features in client_features_map.items():
            if features.request_count == 0:
                continue

            is_anomaly, score = self.predict(features)
            client_result: Dict[str, Any] = {
                "client_id": client_id,
                "is_anomaly": is_anomaly,
                "anomaly_score": score,
                "features": features.to_dict(),
                "alert_created": False,
                "alert_id": None,
                "cooldown_suppressed": False,
            }

            if is_anomaly:
                anomalies_detected_count += 1

                # Cooldown deduplication check
                latest_alert = alert_repo.get_latest_alert_for_rule(
                    client_id=client_id,
                    rule_name=self.RULE_NAME,
                )

                if latest_alert is not None:
                    elapsed = (now - latest_alert.timestamp).total_seconds()
                    if elapsed < cooldown:
                        client_result["cooldown_suppressed"] = True
                        results.append(client_result)
                        continue

                # Create and persist new ML alert
                candidate_alert = self.create_anomaly_alert(
                    features=features,
                    anomaly_score=score,
                    current_time=now,
                )
                persisted = alert_repo.add_alert(candidate_alert)
                client_result["alert_created"] = True
                client_result["alert_id"] = persisted.id
                alerts_created_count += 1

            results.append(client_result)

        return {
            "status": "completed",
            "observation_window_seconds": self.observation_window_seconds,
            "clients_analyzed": len(results),
            "anomalies_detected": anomalies_detected_count,
            "alerts_created": alerts_created_count,
            "results": results,
            "disclaimer": DISCLAIMER_TEXT,
        }


# Global detector singleton
_detector_instance: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    """Dependency provider for AnomalyDetector."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
    return _detector_instance


def set_anomaly_detector(detector: Optional[AnomalyDetector]) -> None:
    """Override active AnomalyDetector instance (useful for testing)."""
    global _detector_instance
    _detector_instance = detector
