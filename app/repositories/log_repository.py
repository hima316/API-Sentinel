"""Request log storage abstraction and in-memory implementation.

This module defines the repository pattern for storing and retrieving request logs.
In Part 2, an in-memory repository is used for simplicity and rapid local development.
In Part 4, a MongoDB repository (e.g., MongoLogRepository) can inherit from
BaseLogRepository and be plugged in without requiring any code changes in endpoints,
middleware, or anomaly detection logic.
"""

from abc import ABC, abstractmethod
from datetime import datetime
import threading
from typing import List, Optional

from pymongo.errors import PyMongoError

from app.core.config import settings
from app.database.mongodb import (
    DatabaseOperationError,
    MongoDBManager,
    get_mongodb_manager,
)
from app.models.log import RequestLog


class BaseLogRepository(ABC):
    """Abstract interface defining required storage operations for request logs."""

    @abstractmethod
    def add_log(self, log_entry: RequestLog) -> RequestLog:
        """Store a new request log entry.

        Args:
            log_entry: The RequestLog instance to persist.

        Returns:
            The persisted RequestLog instance.
        """
        pass

    @abstractmethod
    def get_logs(self, limit: int = 50, skip: int = 0) -> List[RequestLog]:
        """Retrieve recent request logs, sorted in reverse-chronological order (newest first).

        Args:
            limit: Maximum number of records to return.
            skip: Number of records to skip for pagination.

        Returns:
            A list of RequestLog instances.
        """
        pass

    @abstractmethod
    def count_logs(self) -> int:
        """Return the total number of logged requests.

        Returns:
            Total log count as an integer.
        """
        pass

    @abstractmethod
    def get_logs_for_client(
        self,
        client_id: str,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[RequestLog]:
        """Retrieve recent request logs for a specific client.

        Args:
            client_id: Identifier of the client.
            since: Optional IST datetime cutoff to filter logs within a time window.
            limit: Optional maximum number of logs to return.

        Returns:
            List of RequestLog instances ordered newest-first.
        """
        pass

    @abstractmethod
    def clear_logs(self) -> None:
        """Delete all stored logs.

        Useful for test isolation and environment resets.
        """
        pass


class InMemoryLogRepository(BaseLogRepository):
    """Thread-safe in-memory implementation of BaseLogRepository.

    Stores log entries in an internal Python list. Ideal for testing and
    lightweight local development before database integration.
    """

    def __init__(self, max_capacity: int = 10000) -> None:
        """Initialize the in-memory log store with an optional maximum capacity."""
        self._logs: List[RequestLog] = []
        self._lock = threading.Lock()
        self._max_capacity = max_capacity

    def add_log(self, log_entry: RequestLog) -> RequestLog:
        """Append a log entry safely using a thread lock."""
        with self._lock:
            # Enforce max capacity by discarding oldest logs if needed
            if len(self._logs) >= self._max_capacity:
                self._logs.pop(0)
            self._logs.append(log_entry)
        return log_entry

    def get_logs(self, limit: int = 50, skip: int = 0) -> List[RequestLog]:
        """Return recent logs newest-first with pagination."""
        with self._lock:
            # Reverse order so newest requests appear at index 0
            reversed_logs = list(reversed(self._logs))
            return reversed_logs[skip : skip + limit]

    def count_logs(self) -> int:
        """Return the current number of in-memory logs."""
        with self._lock:
            return len(self._logs)

    def get_logs_for_client(
        self,
        client_id: str,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[RequestLog]:
        """Retrieve recent request logs for a specific client, ordered newest first."""
        with self._lock:
            matched: List[RequestLog] = []
            for log in reversed(self._logs):
                if log.client_id == client_id:
                    if since is None or log.timestamp >= since:
                        matched.append(log)
                        if limit is not None and len(matched) >= limit:
                            break
            return matched

    def clear_logs(self) -> None:
        """Clear all in-memory logs."""
        with self._lock:
            self._logs.clear()


class MongoLogRepository(BaseLogRepository):
    """MongoDB implementation of BaseLogRepository for persistent request logging.

    Stores request log records in the configured MongoDB collection with IST timestamps
    and stable UUID identifiers.
    """

    def __init__(self, manager: Optional[MongoDBManager] = None) -> None:
        """Initialize repository with an optional MongoDBManager."""
        self._manager = manager

    @property
    def _collection(self):
        """Return the target request_logs MongoDB collection."""
        manager = self._manager or get_mongodb_manager()
        db = manager.get_database()
        return db[settings.MONGODB_REQUEST_LOGS_COLLECTION]

    def add_log(self, log_entry: RequestLog) -> RequestLog:
        """Persist a RequestLog document into MongoDB."""
        doc = log_entry.model_dump()
        try:
            self._collection.insert_one(doc)
            return log_entry
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to persist request log to MongoDB: {str(exc)}"
            ) from exc

    def get_logs(self, limit: int = 50, skip: int = 0) -> List[RequestLog]:
        """Retrieve recent request logs sorted newest first with pagination."""
        try:
            cursor = (
                self._collection.find()
                .sort("timestamp", -1)
                .skip(skip)
                .limit(limit)
            )
            results: List[RequestLog] = []
            for doc in cursor:
                doc.pop("_id", None)
                results.append(RequestLog.model_validate(doc))
            return results
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to retrieve request logs from MongoDB: {str(exc)}"
            ) from exc

    def get_logs_for_client(
        self,
        client_id: str,
        since: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> List[RequestLog]:
        """Retrieve recent request logs for a specific client, ordered newest first."""
        query = {"client_id": client_id}
        if since is not None:
            query["timestamp"] = {"$gte": since}

        try:
            cursor = self._collection.find(query).sort("timestamp", -1)
            if limit is not None:
                cursor = cursor.limit(limit)

            results: List[RequestLog] = []
            for doc in cursor:
                doc.pop("_id", None)
                results.append(RequestLog.model_validate(doc))
            return results
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to query client logs from MongoDB: {str(exc)}"
            ) from exc

    def count_logs(self) -> int:
        """Return total count of persisted request logs."""
        try:
            return self._collection.count_documents({})
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to count request logs in MongoDB: {str(exc)}"
            ) from exc

    def clear_logs(self) -> None:
        """Delete all request log documents in collection."""
        try:
            self._collection.delete_many({})
        except PyMongoError as exc:
            raise DatabaseOperationError(
                f"Failed to clear request logs in MongoDB: {str(exc)}"
            ) from exc


# Global repository singleton instance
_repository_instance: Optional[BaseLogRepository] = None


def get_log_repository() -> BaseLogRepository:
    """Dependency provider returning the active log repository.

    Selects InMemoryLogRepository or MongoLogRepository based on settings.STORAGE_BACKEND.
    """
    global _repository_instance
    if _repository_instance is None:
        if settings.STORAGE_BACKEND.lower() == "mongodb":
            _repository_instance = MongoLogRepository()
        else:
            _repository_instance = InMemoryLogRepository()
    return _repository_instance


def set_log_repository(repository: BaseLogRepository) -> None:
    """Explicitly override the active log repository (e.g., for testing or Mongo swap)."""
    global _repository_instance
    _repository_instance = repository
