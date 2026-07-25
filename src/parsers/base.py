from abc import ABC, abstractmethod
from datetime import datetime, timezone

# OCSF Authentication (class_uid 3002). type_uid is class_uid * 100 + activity_id.
CLASS_UID_AUTHENTICATION = 3002
CATEGORY_UID_IAM = 3
ACTIVITY_ID_LOGON = 1
STATUS_ID_SUCCESS = 1
STATUS_ID_FAILURE = 2


def to_epoch_millis(value) -> int:
    """OCSF `time` is an integer epoch-millis timestamp, not an ISO string."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def build_authentication_event(status_id: int, raw_time, ip: str, user: str,
                               event_id, product: str, raw_data: str) -> dict:
    """Shared OCSF Authentication envelope so every parser emits one shape."""
    success = status_id == STATUS_ID_SUCCESS
    return {
        "category_uid": CATEGORY_UID_IAM,
        "class_uid": CLASS_UID_AUTHENTICATION,
        "type_uid": CLASS_UID_AUTHENTICATION * 100 + ACTIVITY_ID_LOGON,
        "activity_id": ACTIVITY_ID_LOGON,
        "activity_name": "Logon",
        "status_id": status_id,
        "status": "Success" if success else "Failure",
        "severity_id": 1 if success else 3,
        "time": to_epoch_millis(raw_time),
        "time_dt": raw_time,
        "src_endpoint": {"ip": ip},
        "user": {"name": user},
        "metadata": {
            "version": "1.1.0",
            "product": {"name": product},
            "event_id": event_id,
        },
        "raw_data": raw_data,
    }


class BaseParser(ABC):
    @abstractmethod
    def parse(self, raw_line: str) -> dict:
        """Return an OCSF Authentication event, or None if unparseable/irrelevant."""
