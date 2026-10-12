"""API Sentinel - Main Application Entrypoint.

This module initializes the FastAPI application, mounts the request logging middleware,
registers API routers (authentication, products, and audit logs), and provides system
endpoints such as /health.
"""

import logging
from typing import Any, Dict
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.database.mongodb import DatabaseConnectionError, DatabaseOperationError
from app.middleware.logging import RequestLoggingMiddleware
from app.routes.alerts import router as alerts_router
from app.routes.analysis import router as analysis_router
from app.routes.auth import router as auth_router
from app.routes.logs import router as logs_router
from app.routes.products import router as products_router

logger = logging.getLogger("api_sentinel")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    debug=settings.DEBUG,
)

# Exception handlers to safeguard against leaking database details or stack traces
@app.exception_handler(DatabaseConnectionError)
async def database_connection_exception_handler(
    request: Request, exc: DatabaseConnectionError
) -> JSONResponse:
    logger.error("Database connection failure during request: %s", str(exc))
    return JSONResponse(
        status_code=503,
        content={"detail": "Database service is temporarily unavailable."},
    )


@app.exception_handler(DatabaseOperationError)
async def database_operation_exception_handler(
    request: Request, exc: DatabaseOperationError
) -> JSONResponse:
    logger.error("Database operation failure during request: %s", str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "A database operation error occurred."},
    )


# Register request logging middleware to audit all incoming traffic
app.add_middleware(RequestLoggingMiddleware)

# Register modular API routers
app.include_router(auth_router)
app.include_router(products_router)
app.include_router(logs_router)
app.include_router(alerts_router)
app.include_router(analysis_router)


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Health check endpoint to verify that the service is running.

    Returns:
        JSON response with service status, application name, and environment.
    """
    return {
        "status": "healthy",
        "app_name": settings.PROJECT_NAME,
        "environment": settings.ENVIRONMENT,
        "version": settings.VERSION,
    }


@app.get("/", tags=["System"])
def root() -> Dict[str, Any]:
    """Root endpoint providing service overview and documentation links."""
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "docs_url": "/docs",
        "health_url": "/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
