"""Request logging middleware for API Sentinel.

This middleware intercepts every incoming HTTP request, measures execution time,
extracts safe telemetry metadata (timestamp, client ID, method, path, status,
duration), and stores the record in the active log repository.

SECURITY NOTICE:
This middleware strictly avoids storing sensitive data:
- Request bodies and payloads are never read or stored.
- Passwords, authorization tokens, and API keys are never stored.
- Each request is logged exactly once upon completion.
"""

from datetime import datetime, timezone
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import settings
from app.models.log import RequestLog
from app.repositories.log_repository import get_log_repository
from app.rules.engine import get_detection_engine


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Intercepts and records safe metadata for every incoming HTTP request."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """Process the request, measure response time, and record log metadata."""
        start_time = time.perf_counter()

        # Extract client ID from header (case-insensitive in Starlette headers)
        client_id = request.headers.get(settings.CLIENT_ID_HEADER)
        if not client_id or not client_id.strip():
            client_id = settings.DEFAULT_CLIENT_ID
        else:
            client_id = client_id.strip()

        # Execute downstream route handlers
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            # If an unhandled exception propagates, record HTTP 500 and re-raise
            process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            log_entry = RequestLog(
                timestamp=datetime.now(timezone.utc),
                client_id=client_id,
                method=request.method,
                path=request.url.path,
                status_code=500,
                process_time_ms=process_time_ms,
            )
            get_log_repository().add_log(log_entry)
            raise

        process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Store safe audit record in repository (exactly once per request)
        log_entry = RequestLog(
            timestamp=datetime.now(timezone.utc),
            client_id=client_id,
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            process_time_ms=process_time_ms,
        )
        get_log_repository().add_log(log_entry)

        # Evaluate rule-based abuse detection (monitoring-only, non-blocking)
        try:
            get_detection_engine().evaluate_client(client_id=client_id)
        except Exception:
            # Monitoring failure should never disrupt the client's HTTP response
            pass

        # Add duration header for transparency and observability
        response.headers["X-Process-Time-Ms"] = str(process_time_ms)
        return response
