"""API routes for ML anomaly detection analysis and model status."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.ml.detector import AnomalyDetector, ModelNotFoundError, get_anomaly_detector
from app.repositories.alert_repository import (
    BaseAlertRepository,
    get_alert_repository,
)
from app.repositories.log_repository import (
    BaseLogRepository,
    get_log_repository,
)

router = APIRouter(prefix="/analysis", tags=["ML Anomaly Detection"])


class ClientAnalysisResult(BaseModel):
    """Result of Isolation Forest evaluation for a specific client."""

    client_id: str
    is_anomaly: bool
    anomaly_score: float
    features: Dict[str, Any]
    alert_created: bool
    alert_id: Optional[str] = None
    cooldown_suppressed: bool = False


class AnalysisRunResponse(BaseModel):
    """Summary of ML anomaly detection run across recent traffic."""

    status: str
    observation_window_seconds: int
    clients_analyzed: int
    anomalies_detected: int
    alerts_created: int
    results: List[ClientAnalysisResult]
    disclaimer: str


class ModelStatusResponse(BaseModel):
    """Model status and availability report."""

    model_available: bool
    model_path: str
    metadata_path: str
    model_type: Optional[str] = None
    version: Optional[str] = None
    observation_window_seconds: Optional[int] = None
    feature_names: Optional[List[str]] = None
    contamination: Optional[float] = None
    random_state: Optional[int] = None
    created_at: Optional[str] = None
    error: Optional[str] = None
    setup_instructions: Optional[str] = None
    disclaimer: str


@router.get(
    "/status",
    response_model=ModelStatusResponse,
    summary="Report ML model availability and configuration",
    description=(
        "Returns whether the Isolation Forest model artifact is loaded and ready for "
        "inference, along with model metadata and setup instructions if missing."
    ),
)
def get_model_status(
    detector: AnomalyDetector = Depends(get_anomaly_detector),
) -> ModelStatusResponse:
    """Retrieve the current operational status of the ML model."""
    status_info = detector.get_status()
    return ModelStatusResponse.model_validate(status_info)


@router.post(
    "/run",
    response_model=AnalysisRunResponse,
    summary="Run ML anomaly detection on recent traffic",
    description=(
        "Evaluates recent API traffic over the configured observation window using "
        "Isolation Forest. Persists alerts for anomalous clients while enforcing "
        "cooldown deduplication. Returns HTTP 503 with setup instructions if the model "
        "is missing."
    ),
    responses={
        200: {"description": "Analysis completed successfully"},
        503: {"description": "Model artifact not found; setup required"},
    },
)
def run_analysis(
    client_id: Optional[str] = Query(
        default=None,
        description="Optional target client ID to analyze. If omitted, all active clients in window are evaluated.",
    ),
    cooldown_seconds: Optional[int] = Query(
        default=None,
        ge=0,
        description="Override alert cooldown deduplication window in seconds.",
    ),
    detector: AnomalyDetector = Depends(get_anomaly_detector),
    log_repository: BaseLogRepository = Depends(get_log_repository),
    alert_repository: BaseAlertRepository = Depends(get_alert_repository),
) -> AnalysisRunResponse:
    """Execute Isolation Forest inference against recent request logs."""
    if not detector.is_available():
        detector_status = detector.get_status()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"ML model is not available at '{detector.model_path}'. "
                f"Setup instructions: {detector_status.get('setup_instructions', 'Run python scripts/train_isolation_forest.py')}"
            ),
        )

    # Fetch recent logs from storage to evaluate
    if client_id:
        logs = log_repository.get_logs_for_client(client_id=client_id, limit=500)
    else:
        logs = log_repository.get_logs(limit=1000)

    try:
        report = detector.analyze_traffic(
            logs=logs,
            alert_repo=alert_repository,
            cooldown_seconds=cooldown_seconds,
            target_client_id=client_id,
        )
        return AnalysisRunResponse.model_validate(report)
    except ModelNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
