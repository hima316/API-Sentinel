"""Data storage and repository interfaces."""

from app.repositories.alert_repository import (
    BaseAlertRepository,
    InMemoryAlertRepository,
    MongoAlertRepository,
    get_alert_repository,
    set_alert_repository,
)
from app.repositories.log_repository import (
    BaseLogRepository,
    InMemoryLogRepository,
    MongoLogRepository,
    get_log_repository,
    set_log_repository,
)

__all__ = [
    "BaseAlertRepository",
    "InMemoryAlertRepository",
    "MongoAlertRepository",
    "get_alert_repository",
    "set_alert_repository",
    "BaseLogRepository",
    "InMemoryLogRepository",
    "MongoLogRepository",
    "get_log_repository",
    "set_log_repository",
]
