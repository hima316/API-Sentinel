"""Alert storage abstraction and in-memory implementation.

This module defines the repository interface for storing and retrieving security alerts.
Just like the log repository, the Alert repository pattern allows swapping the
in-memory storage with MongoDB (MongoAlertRepository) in Part 4 without changing
detection logic or API routes.
"""

from abc import ABC, abstractmethod
import threading
from typing import List, Optional

from pymongo.errors import PyMongoError

from app.core.config import settings
from app.database.mongodb import (
    DatabaseOperationError,
    MongoDBManager,
    get_mongodb_manager,
)
from app.models.alert import Alert, AlertStatus


class BaseAlertRepository(ABC):
    """Abstract interface defining storage operations for security alerts."""

    @abstractmethod
    def add_alert(self, alert: Alert) -> Alert:
        """Persist a new security alert."""
        pass

    @abstractmethod
    def get_alerts(
        self,
        limit: int = 50,
        skip: int = 0,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Alert]:
        """Retrieve recent alerts ordered newest first, with optional filtering."""
        pass

    @abstractmethod
    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """Retrieve a single alert by unique ID."""
        pass

    @abstractmethod
    def get_latest_alert_for_rule(
        self, client_id: str, rule_name: str
    ) -> Optional[Alert]:
        """Retrieve the most recent alert for a given client and rule name (for deduplication)."""
        pass

    @abstractmethod
    def count_alerts(self) -> int:
        """Return the total number of stored alerts."""
        pass

    @abstractmethod
    def clear_alerts(self) -> None:
        """Delete all stored alerts (primarily for testing)."""
        pass


class InMemoryAlertRepository(BaseAlertRepository):
    """Thread-safe in-memory implementation of BaseAlertRepository."""

    def __init__(self, max_capacity: int = 5000) -> None:
        """Initialize in-memory alert store."""
        self._alerts: List[Alert] = []
        self._lock = threading.Lock()
        self._max_capacity = max_capacity

    def add_alert(self, alert: Alert) -> Alert:
        """Store an alert safely."""
        with self._lock:
            if len(self._alerts) >= self._max_capacity:
                self._alerts.pop(0)
            self._alerts.append(alert)
        return alert

    def get_alerts(
        self,
        limit: int = 50,
        skip: int = 0,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Alert]:
        """Retrieve alerts ordered newest first with optional filtering."""
        with self._lock:
            results: List[Alert] = []
            for alert in reversed(self._alerts):
                if client_id is not None and alert.client_id != client_id:
                    continue
                if status is not None and alert.status.value != status and alert.status != status:
                    continue
                results.append(alert)

            return results[skip : skip + limit]

    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """Look up an alert by unique identifier."""
        with self._lock:
            for alert in self._alerts:
                if alert.id == alert_id:
                    return alert
            return None

    def get_latest_alert_for_rule(
        self, client_id: str, rule_name: str
    ) -> Optional[Alert]:
        """Find the latest alert for the given client and rule."""
        with self._lock:
            for alert in reversed(self._alerts):
                if alert.client_id == client_id and alert.rule_name == rule_name:
                    return alert
            return None

    def count_alerts(self) -> int:
        """Return the count of stored alerts."""
        with self._lock:
            return len(self._alerts)

    def clear_alerts(self) -> None:
        """Clear all stored alerts."""
        with self._lock:
            self._alerts.clear()


class MongoAlertRepository(BaseAlertRepository):
    """MongoDB implementation of BaseAlertRepository for persistent security alert storage."""

    def __init__(self, manager: Optional[MongoDBManager] = None) -> None:
        """Initialize repository with an optional MongoDBManager."""
        self._manager = manager

    @property
    def _collection(self):
        """Return the target security_alerts MongoDB collection."""
        manager = self._manager or get_mongodb_manager()
        db = manager.get_database()
        return db[settings.MONGODB_SECURITY_ALERTS_COLLECTION]

    def add_alert(self, alert: Alert) -> Alert:
        """Persist a security alert document in MongoDB."""
        doc = alert.model_dump()
        # Ensure enum values are serialized as clean strings
        if "severity" in doc and hasattr(doc["severity"], "value"):
            doc["severity"] = doc["severity"].value
        if "status" in doc and hasattr(doc["status"], "value"):
            doc["status"] = doc["status"].value

        try:
            self._collection.insert_one(doc)
            return alert
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to persist security alert to MongoDB: {str(exc)}"
            ) from exc

    def get_alerts(
        self,
        limit: int = 50,
        skip: int = 0,
        client_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Alert]:
        """Retrieve recent security alerts sorted newest first with optional filtering."""
        query = {}
        if client_id is not None:
            query["client_id"] = client_id
        if status is not None:
            query["status"] = status.value if hasattr(status, "value") else status

        try:
            cursor = (
                self._collection.find(query)
                .sort("timestamp", -1)
                .skip(skip)
                .limit(limit)
            )
            results: List[Alert] = []
            for doc in cursor:
                doc.pop("_id", None)
                results.append(Alert.model_validate(doc))
            return results
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to query security alerts from MongoDB: {str(exc)}"
            ) from exc

    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        """Retrieve an alert by unique identifier."""
        try:
            doc = self._collection.find_one({"id": alert_id})
            if doc is None:
                return None
            doc.pop("_id", None)
            return Alert.model_validate(doc)
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to retrieve alert from MongoDB: {str(exc)}"
            ) from exc

    def get_latest_alert_for_rule(
        self, client_id: str, rule_name: str
    ) -> Optional[Alert]:
        """Retrieve the most recent alert for a specific client and rule name (for deduplication)."""
        try:
            doc = self._collection.find_one(
                {"client_id": client_id, "rule_name": rule_name},
                sort=[("timestamp", -1)],
            )
            if doc is None:
                return None
            doc.pop("_id", None)
            return Alert.model_validate(doc)
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to query latest rule alert from MongoDB: {str(exc)}"
            ) from exc

    def count_alerts(self) -> int:
        """Return total count of stored security alerts."""
        try:
            return self._collection.count_documents({})
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to count security alerts in MongoDB: {str(exc)}"
            ) from exc

    def clear_alerts(self) -> None:
        """Delete all alert documents in collection."""
        try:
            self._collection.delete_many({})
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to clear security alerts in MongoDB: {str(exc)}"
            ) from exc


# Global alert repository singleton instance
_alert_repo_instance: Optional[BaseAlertRepository] = None


def get_alert_repository() -> BaseAlertRepository:
    """Dependency provider returning the active alert repository.

    Selects InMemoryAlertRepository or MongoAlertRepository based on settings.STORAGE_BACKEND.
    """
    global _alert_repo_instance
    if _alert_repo_instance is None:
        if settings.STORAGE_BACKEND.lower() == "mongodb":
            _alert_repo_instance = MongoAlertRepository()
        else:
            _alert_repo_instance = InMemoryAlertRepository()
    return _alert_repo_instance


def set_alert_repository(repository: BaseAlertRepository) -> None:
    """Override the active alert repository instance."""
    global _alert_repo_instance
    _alert_repo_instance = repository
