"""Timezone configuration for API Sentinel.

Defines Indian Standard Time (IST, UTC+05:30) used across logging, alerts, and evaluation.
"""

from datetime import datetime, timedelta, timezone

# Indian Standard Time (UTC+05:30)
IST = timezone(timedelta(hours=5, minutes=30), name="IST")


def now_ist() -> datetime:
    """Return the current datetime in Indian Standard Time (IST)."""
    return datetime.now(IST)
