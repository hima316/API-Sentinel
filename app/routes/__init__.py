"""Route definitions for API Sentinel."""

from app.routes.alerts import router as alerts_router
from app.routes.analysis import router as analysis_router
from app.routes.auth import router as auth_router
from app.routes.logs import router as logs_router
from app.routes.products import router as products_router

__all__ = [
    "alerts_router",
    "analysis_router",
    "auth_router",
    "products_router",
    "logs_router",
]
