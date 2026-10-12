"""MongoDB connection management and Atlas configuration for API Sentinel.

Provides connection pooling, Atlas-compatible timeout settings, credential masking,
and index initialization for the `request_logs` and `security_alerts` collections.
"""

import logging
import re
import threading
from typing import Any, Optional
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, PyMongoError, ServerSelectionTimeoutError

from app.core.config import settings

logger = logging.getLogger("api_sentinel.database")


class DatabaseConnectionError(Exception):
    """Raised when connecting or authenticating to the database fails."""

    pass


class DatabaseOperationError(Exception):
    """Raised when a database query or write operation fails."""

    pass


def mask_mongodb_uri(uri: Optional[str]) -> str:
    """Mask password and credentials in a MongoDB URI string.

    Prevents sensitive credentials from leaking into logs or exception messages.

    Example:
        `mongodb+srv://user:secret123@cluster.mongodb.net/test` ->
        `mongodb+srv://user:****@cluster.mongodb.net/test`
    """
    if not uri:
        return "<unset>"

    # Match protocol://username:password@host
    pattern = r"(mongodb(?:\+srv)?:\/\/[^:]+:)([^@]+)(@)"
    return re.sub(pattern, r"\1****\3", uri)


def is_configured_mongodb_uri(uri: Optional[str]) -> bool:
    """Check if a MongoDB URI string is configured with non-empty, non-placeholder values.

    Returns False if uri is None, empty/whitespace, or contains template placeholders
    such as `<username>` or `<password>`.
    """
    if not uri or not uri.strip():
        return False
    # Detect unconfigured template placeholders like <username>, <password>
    if "<" in uri and ">" in uri:
        return False
    return True


_UNSET: Any = object()


class MongoDBManager:
    """Thread-safe manager for MongoClient and Database instances."""

    def __init__(
        self,
        uri: Optional[str] = _UNSET,
        database_name: Optional[str] = None,
    ) -> None:
        """Initialize MongoDB manager.

        Args:
            uri: MongoDB connection string (defaults to settings.MONGODB_URI).
            database_name: Target database name (defaults to settings.MONGODB_DATABASE).
        """
        if uri is _UNSET:
            self._uri = settings.MONGODB_URI
        else:
            self._uri = uri

        self._database_name = database_name or settings.MONGODB_DATABASE
        self._client: Optional[MongoClient] = None
        self._db: Optional[Database] = None
        self._lock = threading.RLock()
        self._indexes_initialized = False

    @property
    def masked_uri(self) -> str:
        """Return the connection URI with credentials safely redacted."""
        return mask_mongodb_uri(self._uri)

    def get_client(self) -> MongoClient:
        """Return a verified MongoClient instance.

        Raises:
            DatabaseConnectionError: If connection cannot be established or verified.
        """
        with self._lock:
            if self._client is None:
                if not is_configured_mongodb_uri(self._uri):
                    raise DatabaseConnectionError(
                        "MongoDB URI is not configured. Set MONGODB_URI in your environment."
                    )

                try:
                    # Configure Atlas-compatible MongoClient
                    self._client = MongoClient(
                        self._uri,
                        connectTimeoutMS=settings.MONGODB_CONNECT_TIMEOUT_MS,
                        serverSelectionTimeoutMS=settings.MONGODB_SERVER_SELECTION_TIMEOUT_MS,
                        appname="API-Sentinel",
                        retryWrites=True,
                    )
                    # Verify connectivity immediately with a lightweight ping command
                    self._client.admin.command("ping")
                    logger.info("Successfully connected to MongoDB (%s)", self.masked_uri)
                except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
                    self._client = None
                    raise DatabaseConnectionError(
                        f"Failed to connect to MongoDB ({self.masked_uri}): {str(exc)}"
                    ) from exc
                except PyMongoError as exc:
                    self._client = None
                    raise DatabaseConnectionError(
                        f"MongoDB configuration error ({self.masked_uri}): {str(exc)}"
                    ) from exc

            return self._client

    def get_database(self) -> Database:
        """Return the target MongoDB Database instance with indexes ensured."""
        with self._lock:
            if self._db is None:
                client = self.get_client()
                self._db = client[self._database_name]
                self._init_indexes(self._db)
            return self._db

    def _init_indexes(self, db: Database) -> None:
        """Create necessary indexes for performance and data integrity."""
        if self._indexes_initialized:
            return

        try:
            # 1. Indexes on request_logs collection
            logs_col = db[settings.MONGODB_REQUEST_LOGS_COLLECTION]
            logs_col.create_index([("id", 1)], unique=True, name="idx_logs_id_unique")
            logs_col.create_index([("timestamp", -1)], name="idx_logs_timestamp_desc")
            logs_col.create_index(
                [("client_id", 1), ("timestamp", -1)],
                name="idx_logs_client_timestamp",
            )

            # 2. Indexes on security_alerts collection
            alerts_col = db[settings.MONGODB_SECURITY_ALERTS_COLLECTION]
            alerts_col.create_index(
                [("id", 1)], unique=True, name="idx_alerts_id_unique"
            )
            alerts_col.create_index(
                [("timestamp", -1)], name="idx_alerts_timestamp_desc"
            )
            alerts_col.create_index(
                [("client_id", 1), ("rule_name", 1), ("timestamp", -1)],
                name="idx_alerts_client_rule_timestamp",
            )
            alerts_col.create_index([("status", 1)], name="idx_alerts_status")

            self._indexes_initialized = True
            logger.info("MongoDB indexes successfully initialized.")
        except PyMongoError as exc:
            logger.warning("Could not create MongoDB indexes: %s", str(exc))

    def close(self) -> None:
        """Close the active MongoClient connection."""
        with self._lock:
            if self._client is not None:
                self._client.close()
                self._client = None
                self._db = None
                self._indexes_initialized = False


# Global MongoDB manager singleton
_mongo_manager_instance: Optional[MongoDBManager] = None


def get_mongodb_manager() -> MongoDBManager:
    """Dependency provider for MongoDBManager."""
    global _mongo_manager_instance
    if _mongo_manager_instance is None:
        _mongo_manager_instance = MongoDBManager()
    return _mongo_manager_instance


def set_mongodb_manager(manager: MongoDBManager) -> None:
    """Override MongoDBManager instance (useful for testing)."""
    global _mongo_manager_instance
    _mongo_manager_instance = manager
