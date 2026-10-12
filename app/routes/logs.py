"""Audit logs retrieval routes."""

from typing import List
from fastapi import APIRouter, Depends, Query

from app.core.config import settings
from app.models.log import RequestLog
from app.repositories.log_repository import BaseLogRepository, get_log_repository

router = APIRouter(prefix="/logs", tags=["Audit Logs"])


@router.get(
    "",
    response_model=List[RequestLog],
    summary="Get recent request logs",
    description=(
        "Returns recent request metadata recorded by the logging middleware, "
        "ordered newest first. Excludes sensitive request payloads."
    ),
)
def get_recent_logs(
    limit: int = Query(
        default=settings.DEFAULT_LOGS_LIMIT,
        ge=1,
        le=settings.MAX_LOGS_LIMIT,
        description=f"Maximum number of logs to return (1 to {settings.MAX_LOGS_LIMIT})",
    ),
    skip: int = Query(
        default=0,
        ge=0,
        description="Number of log records to skip for pagination",
    ),
    repository: BaseLogRepository = Depends(get_log_repository),
) -> List[RequestLog]:
    """Retrieve recent audited request records."""
    return repository.get_logs(limit=limit, skip=skip)
